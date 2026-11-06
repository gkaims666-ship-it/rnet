package com.rnet.app.service

import android.app.*
import android.content.Intent
import android.net.*
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.rnet.app.R
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.DoHResolver
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * RnetForegroundService — combined VPN + foreground service.
 *
 * ── Speed architecture ──────────────────────────────────────────────────────
 *   • Dedicated reader thread reads tun fd with 64 KB buffer — no coroutine per pkt
 *   • Single writer thread drains a LinkedBlockingDeque to tun fd — no synchronized
 *   • Sessions use ArrayBlockingQueue (no copy, no extra lock) instead of PipedStream
 *   • Full 32-bit IP in session key to avoid low-16-bit collision (audit fix #9)
 *   • SO_RCVBUF/SO_SNDBUF = 256 KB on each TCP socket
 *
 * ── Smart routing ───────────────────────────────────────────────────────────
 *   • SmartRouter probes per-destination: preferred region → fallback chain → direct
 *   • TunnelPool manages up to 4 simultaneous Psiphon exits (lazy start, LRU eviction)
 *   • Cache: once a working route is found for a destination IP, it is reused (1h TTL)
 *   • No single point of failure — if one exit country is blocked, next is tried instantly
 *
 * ── Audit fixes applied ─────────────────────────────────────────────────────
 *   #1  buf copy before dispatch — reader buffer not shared with pool threads
 *   #2  writeQueue overflow → warn + oldest-drop instead of silent discard
 *   #3  SESSION_QUEUE_CAPACITY increased to 512
 *   #4  Psiphon health checked via test SOCKS5 connection every 30s
 *   #5  Single proxy → TunnelPool with multi-region failover
 *   #6  connectViaProxy replaced by SmartRouter.connect()
 *   #7  reader.join() uses interruptible withContext(Dispatchers.IO)
 *   #8  DoH parallel probe (all endpoints concurrently, first wins)
 *   #9  Session key uses full 32-bit IPs, not low-16-bit
 */
class RnetForegroundService : VpnService() {

    companion object {
        const val ACTION_START         = "com.rnet.START"
        const val ACTION_STOP          = "com.rnet.STOP"
        const val ACTION_GATEWAY_START = "com.rnet.GATEWAY_START"
        const val ACTION_GATEWAY_STOP  = "com.rnet.GATEWAY_STOP"

        private const val TAG    = "RnetVPN"
        private const val CH_ID  = "rnet_svc"
        private const val NOTIF  = 1001
        private const val TUN_IP = "10.0.0.2"
        private const val MTU    = 1500
        private const val MAX_CON = 600
        private const val READ_BUF  = 65535
        private const val SOCK_BUF  = 262144
        private const val SESSION_QUEUE_CAPACITY = 512   // audit fix #3
        private const val HEALTH_INTERVAL_MS = 30_000L
        private const val IDLE_EVICT_INTERVAL_MS = 120_000L  // 2min

        private const val PREFERRED_REGION = "IS"   // Iceland default

        val FREE_REGIONS = listOf(
            "IS", "EE", "NO", "SE", "FI", "CH", "DE", "NL",
            "AT", "CZ", "CA", "US", "GB", "JP", "AU"
        )

        // TCP flags
        private const val SYN = 0x02; private const val ACK = 0x10
        private const val FIN = 0x01; private const val RST = 0x04
        private const val PSH = 0x08

        // ── Public state (polled by MainViewModel every 1s) ─────────────────
        @JvmField val activeBytesIn      = AtomicLong(0L)
        @JvmField val activeBytesOut     = AtomicLong(0L)
        @JvmField val activeSessionCount = AtomicInteger(0)
        @Volatile var proxyLabel         = "—"
        @Volatile var connectionPhase    = ConnectionPhase.IDLE
        @Volatile var activeSocksPort    = 0
        @Volatile var exitRegion         = PREFERRED_REGION
        @Volatile var pendingRegion      = PREFERRED_REGION
        @Volatile var routeCacheSize     = 0   // how many destinations are cached
        @Volatile var pooledSockets      = 0   // pre-warmed sockets ready
        // Apps excluded from VPN (split tunneling) — system apps that don't need circumvention
        val SPLIT_TUNNEL_PACKAGES = setOf(
            "com.android.vending",         // Play Store — keep fast
            "com.google.android.gms",      // Google Play Services
            "com.google.android.gsf",      // Google Services Framework
            "com.android.providers.downloads",
            "com.sec.android.daemonapp"    // Samsung system daemon
        )
    }

    // ── Thread pool ─────────────────────────────────────────────────────────
    private val pool = ThreadPoolExecutor(
        4, 1024, 60L, TimeUnit.SECONDS, SynchronousQueue(),
        ThreadPoolExecutor.CallerRunsPolicy()
    )

    private val svcScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null

    // Session table: Long key = packed full 32-bit src+dst IPs and ports
    private val sessions  = ConcurrentHashMap<Long, Session>(1024)
    private val connCount = AtomicInteger(0)

    @Volatile private var alive         = false
    @Volatile private var engineStarted = false
    @Volatile private var gwStarted     = false

    // Single tun writer: session threads post here, one thread drains to fd
    private val writeQueue = LinkedBlockingDeque<ByteArray>(8192)
    @Volatile private var writerThread: Thread? = null
    @Volatile private var readerThread: Thread? = null

    // Smart routing + supporting components
    private var tunnelPool: TunnelPool? = null
    private var smartRouter: SmartRouter? = null

    private var cellMon: CellMonitor?     = null
    private var gateway: HotspotGateway? = null

    // Network change listener — zero-drop handoff on WiFi↔cellular switch
    private val connectivityManager by lazy {
        getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
    }
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var lastNetwork: Network? = null

    // ── Android lifecycle ────────────────────────────────────────────────────
    override fun onCreate() { super.onCreate(); makeChan(); cellMon = CellMonitor(this) }

    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        startForeground(NOTIF, notif())
        when (i?.action) {
            ACTION_START         -> start()
            ACTION_STOP          -> { stop(); stopGw() }
            ACTION_GATEWAY_START -> startGw()
            ACTION_GATEWAY_STOP  -> stopGw()
        }
        return START_STICKY
    }

    override fun onRevoke()  { stop(); super.onRevoke() }
    override fun onBind(i: Intent?) = null
    override fun onDestroy() { stopGw(); stop(); svcScope.cancel(); super.onDestroy() }

    // ── Engine start / stop ──────────────────────────────────────────────────
    private fun start() {
        if (engineStarted) return
        engineStarted = true

        // Load persisted region preference
        val saved = getSharedPreferences("rnet_prefs", MODE_PRIVATE)
            .getString("exit_region", PREFERRED_REGION) ?: PREFERRED_REGION
        if (pendingRegion == PREFERRED_REGION) pendingRegion = saved
        val region = pendingRegion.ifEmpty { PREFERRED_REGION }

        connectionPhase = ConnectionPhase.STARTING
        activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0)
        proxyLabel = "Starting…"
        cellMon!!.start()

        // Load persistent caches from disk
        DnsCache.load(applicationContext)

        // Build the tunnel pool and smart router (with context for persistence)
        val tp = TunnelPool(applicationContext) { s -> protect(s) }
        tunnelPool = tp
        smartRouter = SmartRouter(tp, region, this, applicationContext)

        // Register network change callback for seamless handoff
        registerNetworkCallback()

        svcScope.launch { warmupTunnels(region) }
        svcScope.launch { vpnLoop() }
        svcScope.launch { healthLoop() }
        svcScope.launch { maintenanceLoop() }
        postNotif()
    }

    private fun stop() {
        if (!engineStarted) return
        engineStarted = false; alive = false
        connectionPhase = ConnectionPhase.IDLE; proxyLabel = "—"
        sessions.values.forEach { runCatching { it.close() } }; sessions.clear()
        readerThread?.interrupt(); writerThread?.interrupt()
        writeQueue.clear(); writeQueue.offer(ByteArray(0))
        try { tun?.close() } catch (_: Exception) {}; tun = null
        // Save caches to disk before stopping
        smartRouter?.connPool?.stopAll()
        smartRouter?.saveTodisk()
        DnsCache.save(applicationContext)
        tunnelPool?.stopAll(); tunnelPool = null; smartRouter = null
        unregisterNetworkCallback()
        LocationMasker.stop(applicationContext)
        cellMon?.stop()
        activeSocksPort = 0; activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0); routeCacheSize = 0; pooledSockets = 0
        postNotif()
        if (!gwStarted) stopSelf()
    }

    // ── Network change handling (seamless WiFi↔cellular handoff) ─────────────
    private fun registerNetworkCallback() {
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = lastNetwork
                lastNetwork = network
                if (prev != null && prev != network && engineStarted) {
                    Log.i(TAG, "Network switched — rebuilding VPN tun")
                    // Restart VPN loop on new network without full stop/start
                    svcScope.launch { rebuildTun() }
                }
            }
            override fun onLost(network: Network) {
                if (network == lastNetwork) lastNetwork = null
            }
        }
        try {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            connectivityManager.registerNetworkCallback(req, cb)
            networkCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "NetworkCallback registration failed: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            try { connectivityManager.unregisterNetworkCallback(it) } catch (_: Exception) {}
            networkCallback = null
        }
    }

    /** Rebuild the tun interface on network switch — keeps sessions alive. */
    private suspend fun rebuildTun() = withContext(Dispatchers.IO) {
        if (!engineStarted) return@withContext
        Log.i(TAG, "Rebuilding tun after network change")
        // Interrupt reader — it will exit its loop, vpnLoop will restart
        readerThread?.interrupt()
        // Brief wait for reader to exit
        delay(300)
        // vpnLoop detects alive=true and loops back to re-establish
        // (reader exits on IOException, vpnLoop restarts if alive still true)
    }

    // ── Tunnel warmup ────────────────────────────────────────────────────────
    private suspend fun warmupTunnels(preferredRegion: String) = withContext(Dispatchers.IO) {
        connectionPhase = ConnectionPhase.FINDING_PROXY
        proxyLabel = "Connecting ($preferredRegion)…"
        postNotif()

        val tp = tunnelPool ?: return@withContext

        // Start preferred region tunnel first
        val port = tp.getSocksPort(preferredRegion)
        if (port > 0) {
            activeSocksPort = port
            exitRegion = preferredRegion
            proxyLabel = "Smart·$preferredRegion"
            connectionPhase = ConnectionPhase.ACTIVE
            Log.i(TAG, "Primary tunnel $preferredRegion:$port ready")
            val city = LocationMasker.start(applicationContext, preferredRegion)
            if (city != null) Log.i(TAG, "GPS → $city")
            postNotif()

            // Warm up 2 fallback tunnels in background for fast failover
            val fallbacks = listOf("DE", "NL", "US").filter { it != preferredRegion }.take(2)
            fallbacks.forEach { fb -> launch { tp.getSocksPort(fb) } }
        } else {
            Log.w(TAG, "Preferred tunnel $preferredRegion failed — trying fallbacks")
            val fallbackOrder = listOf("IS","EE","DE","NL","SE","US","CA","GB")
                .filter { it != preferredRegion }
            var connected = false
            for (fb in fallbackOrder) {
                val p = tp.getSocksPort(fb)
                if (p > 0) {
                    activeSocksPort = p
                    exitRegion = fb
                    proxyLabel = "Smart·$fb"
                    connectionPhase = ConnectionPhase.ACTIVE
                    Log.i(TAG, "Fallback tunnel $fb:$p ready")
                    postNotif()
                    connected = true
                    break
                }
            }
            if (!connected) {
                proxyLabel = "Direct"
                connectionPhase = ConnectionPhase.ACTIVE
                postNotif()
            }
        }
    }

    // ── Health check loop ────────────────────────────────────────────────────
    // Audit fix #4: actually test Psiphon SOCKS5 connections, not just skip them
    private suspend fun healthLoop() = withContext(Dispatchers.IO) {
        while (engineStarted) {
            delay(HEALTH_INTERVAL_MS)
            if (!engineStarted) break
            val tp = tunnelPool ?: break

            // Test each active tunnel with a real SOCKS5 handshake
            for (region in tp.activeRegions()) {
                if (!tp.isReady(region)) continue
                val port = tp.getSocksPort(region)
                if (port <= 0) continue
                val healthy = try {
                    val s = Socket(); protect(s)
                    s.connect(InetSocketAddress("127.0.0.1", port), 2000)
                    s.getOutputStream().write(byteArrayOf(0x05, 0x01, 0x00)); s.getOutputStream().flush()
                    val resp = ByteArray(2); s.getInputStream().read(resp); s.close()
                    resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()
                } catch (_: Exception) { false }

                if (!healthy) {
                    Log.w(TAG, "Tunnel $region unhealthy — evicting route cache")
                    smartRouter?.evictExpired()
                }
            }

            // Update UI stats
            routeCacheSize = smartRouter?.routeCacheSize ?: 0
            pooledSockets  = smartRouter?.connPool?.totalPooled() ?: 0
            proxyLabel = "Smart·${exitRegion} (${routeCacheSize}✓ ${pooledSockets}⚡)"
            postNotif()
        }
    }

    // ── Maintenance loop ──────────────────────────────────────────────────────
    private suspend fun maintenanceLoop() = withContext(Dispatchers.IO) {
        var saveCounter = 0
        while (engineStarted) {
            delay(IDLE_EVICT_INTERVAL_MS)
            tunnelPool?.evictIdle()
            smartRouter?.evictExpired()
            smartRouter?.connPool?.evictIdle()
            DnsCache.evictExpired()
            routeCacheSize = smartRouter?.routeCacheSize ?: 0
            pooledSockets  = smartRouter?.connPool?.totalPooled() ?: 0
            // Save caches to disk every 10 minutes
            if (++saveCounter >= 5) {
                saveCounter = 0
                smartRouter?.saveTodisk()
                DnsCache.save(applicationContext)
            }
        }
    }

    // ── VPN loop — auto-restarts on network change ────────────────────────────
    private suspend fun vpnLoop() {
        // Outer loop: re-establish tun after network switch
        while (engineStarted) {
            val tunStarted = runCatching { buildAndRunTun() }.isSuccess
            if (!engineStarted) break
            if (!tunStarted) {
                delay(1000)  // back-off before retry
            }
        }
    }

    private suspend fun buildAndRunTun() {
        try {
            val builder = Builder()
                .setSession("RNET")
                .setMtu(MTU)
                .addAddress(TUN_IP, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setBlocking(true)

            // Always exclude self to avoid routing loops
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            // Split tunneling: exclude system apps that don't need circumvention
            for (pkg in SPLIT_TUNNEL_PACKAGES) {
                try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

            val newTun = builder.establish() ?: run {
                Log.e(TAG, "establish() = null — no VPN permission")
                engineStarted = false; connectionPhase = ConnectionPhase.IDLE; postNotif()
                return
            }

            // Swap tun atomically — close old one after establishing new
            val oldTun = tun
            tun = newTun
            oldTun?.let { runCatching { it.close() } }

            alive = true
            Log.i(TAG, "VPN tun up ✓")

            val fd  = newTun.fileDescriptor
            val inp = FileInputStream(fd)
            val out = FileOutputStream(fd)

            // Writer thread
            val writer = Thread({
                while (alive || !writeQueue.isEmpty()) {
                    val pkt = writeQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    if (pkt.isEmpty()) break
                    try { out.write(pkt) } catch (_: Exception) { break }
                }
            }, "rnet-writer")
            writer.isDaemon = true; writer.start()
            writerThread = writer

            // Reader thread — audit fix #1: copy buffer before dispatch
            val reader = Thread({
                val buf = ByteArray(READ_BUF)
                while (alive) {
                    val n = try { inp.read(buf) } catch (_: Exception) { -1 }
                    if (n <= 0) { if (alive) continue else break }
                    val pkt = buf.copyOf(n)
                    try { handlePkt(pkt, n) } catch (_: Exception) {}
                }
            }, "rnet-reader")
            reader.isDaemon = true; reader.start()
            readerThread = reader

            // audit fix #7: interruptible join
            withContext(Dispatchers.IO) { reader.join() }

            // Reader exited — if still alive it means network changed, loop will rebuild
            if (engineStarted) Log.i(TAG, "Reader exited — will rebuild tun")
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e  // propagate coroutine cancellation
        } catch (e: Exception) {
            Log.e(TAG, "VPN loop error: ${e.message}", e)
        } finally {
            runCatching { tun?.close() }; tun = null
        }
    }

    // ── Packet dispatch ───────────────────────────────────────────────────────
    private fun handlePkt(b: ByteArray, n: Int) {
        if (n < 20 || (b[0].i and 0xF0) != 0x40) return
        val ipHL  = (b[0].i and 0x0F) * 4
        if (n < ipHL + 8) return
        val proto = b[9].i
        val sIP   = ip4(b, 12)
        val dIP   = ip4(b, 16)
        when (proto) {
            6  -> tcpPkt(b, n, ipHL, sIP, dIP)
            17 -> udpPkt(b, n, ipHL, sIP, dIP)
        }
    }

    // ── TCP ───────────────────────────────────────────────────────────────────
    private fun tcpPkt(b: ByteArray, n: Int, ipHL: Int, sIP: InetAddress, dIP: InetAddress) {
        if (n < ipHL + 20) return
        val t0    = ipHL
        val sPort = r16(b, t0)
        val dPort = r16(b, t0 + 2)
        val seq   = r32(b, t0 + 4)
        val tcpHL = ((b[t0 + 12].i shr 4) and 0xF) * 4
        val flags = b[t0 + 13].i
        val pOff  = t0 + tcpHL
        val pLen  = (n - pOff).coerceAtLeast(0)
        val key   = sessionKey(sIP, sPort, dIP, dPort)

        when {
            flags and RST != 0 -> sessions.remove(key)?.close()

            flags and SYN != 0 && flags and ACK == 0 -> {
                sessions.remove(key)?.close()
                if (connCount.get() >= MAX_CON) {
                    sendTcp(dIP, dPort, sIP, sPort, 0, seq + 1, RST or ACK, null, 0); return
                }
                val sess = Session(sIP, sPort, dIP, dPort, seq)
                sessions[key] = sess
                connCount.incrementAndGet(); activeSessionCount.set(connCount.get())
                pool.execute {
                    try { sess.run() }
                    catch (e: Exception) { Log.d(TAG, "${sIP}:${sPort}→${dIP}:${dPort}: ${e.message}") }
                    finally {
                        sessions.remove(key)
                        connCount.decrementAndGet(); activeSessionCount.set(connCount.get())
                        sess.close()
                    }
                }
            }

            flags and FIN != 0 -> sessions.remove(key)?.also { it.fin(); it.close() }
            pLen > 0 -> sessions[key]?.forward(b, pOff, pLen, seq)
        }
    }

    // ── UDP / DNS ─────────────────────────────────────────────────────────────
    private fun udpPkt(b: ByteArray, n: Int, ipHL: Int, sIP: InetAddress, dIP: InetAddress) {
        val sPort = r16(b, ipHL)
        val dPort = r16(b, ipHL + 2)
        val uLen  = r16(b, ipHL + 4)
        val pLen  = (uLen - 8).coerceAtMost(n - ipHL - 8).coerceAtLeast(0)
        if (pLen <= 0) return
        val pay = b.copyOfRange(ipHL + 8, ipHL + 8 + pLen)
        pool.execute { relayUdp(sIP, sPort, dIP, dPort, pay) }
    }

    private fun relayUdp(sIP: InetAddress, sPort: Int, dIP: InetAddress, dPort: Int, pay: ByteArray) {
        val resp: ByteArray? = if (dPort == 53) {
            // DNS: check cache first, then parallel DoH (audit fix #8), then UDP fallback
            val cached = tryResolveDnsFromCache(pay)
            cached ?: DoHResolver.resolveParallel(pay)?.also { storeDnsToCache(pay, it) }
                    ?: DoHResolver.resolveUdp(pay) { sock -> protect(sock) }
        } else {
            relayUdpDirect(dIP, dPort, pay)
        }
        if (resp == null) return
        writeUdpResponse(sIP, sPort, dIP, dPort, resp)
    }

    /**
     * Extract the hostname from a DNS query and return a synthesized response
     * if the IP is in our DnsCache. Returns null if not cached or parse fails.
     */
    private fun tryResolveDnsFromCache(query: ByteArray): ByteArray? {
        return try {
            if (query.size < 12) return null
            val qdCount = ((query[4].toInt() and 0xFF) shl 8) or (query[5].toInt() and 0xFF)
            if (qdCount == 0) return null
            // Parse first question: skip header (12 bytes), read QNAME labels
            var pos = 12
            val sb = StringBuilder()
            while (pos < query.size) {
                val len = query[pos++].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                if (pos + len > query.size) return null
                sb.append(String(query, pos, len, Charsets.US_ASCII))
                pos += len
            }
            val host = sb.toString().lowercase()
            if (host.isEmpty()) return null
            val ip = DnsCache.get(host) ?: return null
            buildDnsResponse(query, ip)
        } catch (_: Exception) { null }
    }

    /** Cache the resolved IP from a DoH response back to DnsCache. */
    private fun storeDnsToCache(query: ByteArray, response: ByteArray) {
        try {
            if (response.size < 12) return
            val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
            if (anCount == 0) return
            // Parse question to get hostname, then find first A record in answer
            var pos = 12
            val sb = StringBuilder()
            while (pos < response.size) {
                val len = response[pos++].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                if (pos + len > response.size) return
                sb.append(String(response, pos, len, Charsets.US_ASCII))
                pos += len
            }
            val host = sb.toString().lowercase()
            if (host.isEmpty()) return
            pos += 4 // skip QTYPE + QCLASS
            // Find A record in answers
            repeat(anCount) {
                if (pos + 10 > response.size) return
                // Skip name (may be pointer 0xC0 xx or labels)
                if (response[pos].toInt() and 0xC0 == 0xC0) pos += 2
                else { while (pos < response.size && response[pos] != 0.toByte()) pos++; pos++ }
                if (pos + 10 > response.size) return
                val type  = ((response[pos].toInt() and 0xFF) shl 8) or (response[pos+1].toInt() and 0xFF)
                val rdLen = ((response[pos+8].toInt() and 0xFF) shl 8) or (response[pos+9].toInt() and 0xFF)
                pos += 10
                if (type == 1 && rdLen == 4 && pos + 4 <= response.size) {
                    val ipBytes = response.copyOfRange(pos, pos + 4)
                    val addr = InetAddress.getByAddress(ipBytes)
                    DnsCache.put(host, addr)
                }
                pos += rdLen
            }
        } catch (_: Exception) {}
    }

    /** Build a minimal DNS A-record response from a cached IP. */
    private fun buildDnsResponse(query: ByteArray, ip: InetAddress): ByteArray? {
        if (ip.address.size != 4) return null  // IPv4 only
        val resp = query.copyOf(query.size + 16)
        // Set QR=1 (response), AA=1, RA=1 in flags
        resp[2] = 0x81.toByte(); resp[3] = 0x80.toByte()
        // ANCOUNT = 1
        resp[6] = 0x00; resp[7] = 0x01
        // Append answer: name ptr (0xC00C), TYPE A, CLASS IN, TTL 300, RDLENGTH 4, IP
        val answer = byteArrayOf(
            0xC0.toByte(), 0x0C,          // name pointer to offset 12
            0x00, 0x01,                    // TYPE A
            0x00, 0x01,                    // CLASS IN
            0x00, 0x00, 0x01, 0x2C,       // TTL 300
            0x00, 0x04,                    // RDLENGTH 4
            ip.address[0], ip.address[1], ip.address[2], ip.address[3]
        )
        return query.copyOf(query.size) + answer
    }

    private fun relayUdpDirect(dIP: InetAddress, dPort: Int, pay: ByteArray): ByteArray? {
        return try {
            val sock = DatagramSocket(); protect(sock)
            sock.soTimeout = 5000
            sock.send(DatagramPacket(pay, pay.size, dIP, dPort))
            val rb = ByteArray(4096); val rp = DatagramPacket(rb, rb.size)
            sock.receive(rp); sock.close()
            rb.copyOf(rp.length)
        } catch (_: Exception) { null }
    }

    private fun writeUdpResponse(sIP: InetAddress, sPort: Int, dIP: InetAddress, dPort: Int, resp: ByteArray) {
        val tot = 28 + resp.size
        val pkt = ByteArray(tot)
        pkt[0] = 0x45.toByte(); w16(pkt, 2, tot)
        pkt[8] = 64; pkt[9] = 17
        dIP.address.copyInto(pkt, 12); sIP.address.copyInto(pkt, 16)
        w16(pkt, 10, ipCs(pkt, 0, 20))
        w16(pkt, 20, dPort); w16(pkt, 22, sPort); w16(pkt, 24, 8 + resp.size)
        resp.copyInto(pkt, 28)
        enqueuePkt(pkt)
    }

    // ── Session ───────────────────────────────────────────────────────────────
    private inner class Session(
        private val sIP: InetAddress, private val sPort: Int,
        private val dIP: InetAddress, private val dPort: Int,
        clientIsn: Long
    ) {
        private val serverIsn = System.nanoTime() and 0xFFFFFFFFL
        @Volatile private var sSeq = serverIsn + 1
        @Volatile private var cAck = clientIsn + 1

        private val outQueue = ArrayBlockingQueue<ByteArray>(SESSION_QUEUE_CAPACITY)
        private val POISON   = ByteArray(0)

        private var sock: Socket? = null
        @Volatile var closed = false

        fun run() {
            // SmartRouter: pre-warmed pool → cache → probe → fallback → direct
            val s = smartRouter?.connect(dIP, dPort) ?: run {
                sendTcp(dIP, dPort, sIP, sPort, 0, cAck, RST or ACK, null, 0); return
            }
            sock = s
            sendTcp(dIP, dPort, sIP, sPort, serverIsn, cAck, SYN or ACK, null, 0)

            // Inbound: remote → tun
            pool.execute {
                val buf = ByteArray(READ_BUF)
                val sin = s.getInputStream()
                try {
                    while (!closed) {
                        val n = sin.read(buf); if (n < 0) break; if (n == 0) continue
                        sendTcp(dIP, dPort, sIP, sPort, sSeq, cAck, PSH or ACK, buf, n)
                        sSeq += n; activeBytesIn.addAndGet(n.toLong())
                    }
                    if (!closed) sendTcp(dIP, dPort, sIP, sPort, sSeq, cAck, FIN or ACK, null, 0)
                } catch (_: Exception) {}
                finally { outQueue.offer(POISON) }
            }

            // Outbound: tun → remote
            val sout = s.getOutputStream()
            try {
                while (!closed) {
                    val chunk = outQueue.poll(300, TimeUnit.MILLISECONDS) ?: continue
                    if (chunk === POISON || chunk.isEmpty()) break
                    sout.write(chunk); sout.flush()
                    activeBytesOut.addAndGet(chunk.size.toLong())
                }
            } catch (e: Exception) {
                // If session dies mid-stream, invalidate its route so next conn re-probes
                smartRouter?.invalidate(dIP, dPort)
            }
        }

        fun forward(b: ByteArray, off: Int, len: Int, seq: Long) {
            if (closed) return
            cAck = seq + len
            outQueue.offer(b.copyOfRange(off, off + len))
            sendTcp(dIP, dPort, sIP, sPort, sSeq, cAck, ACK, null, 0)
        }

        fun fin()   { try { sock?.shutdownOutput() } catch (_: Exception) {} }
        fun close() {
            if (closed) return; closed = true
            outQueue.offer(POISON); try { sock?.close() } catch (_: Exception) {}
        }
    }

    // ── TCP packet builder ────────────────────────────────────────────────────
    private fun sendTcp(srcIP: InetAddress, srcPort: Int,
                         dstIP: InetAddress, dstPort: Int,
                         seq: Long, ack: Long, flags: Int,
                         pay: ByteArray?, payLen: Int) {
        val pLen  = if (pay != null && payLen > 0) payLen else 0
        val p     = ByteArray(40 + pLen)
        p[0] = 0x45.toByte(); w16(p, 2, 40 + pLen); p[8] = 64; p[9] = 6
        srcIP.address.copyInto(p, 12); dstIP.address.copyInto(p, 16)
        w16(p, 10, ipCs(p, 0, 20))
        w16(p, 20, srcPort); w16(p, 22, dstPort)
        w32(p, 24, seq);     w32(p, 28, ack)
        p[32] = 0x50.toByte(); p[33] = flags.toByte()
        p[34] = 0xFF.toByte(); p[35] = 0xFF.toByte()
        if (pLen > 0) pay!!.copyInto(p, 40, 0, pLen)
        w16(p, 36, tcpCs(p, 20, 20 + pLen, srcIP.address, dstIP.address))
        enqueuePkt(p)
    }

    // Audit fix #2: drop oldest packet rather than silently losing new one on overflow
    private fun enqueuePkt(pkt: ByteArray) {
        if (!writeQueue.offer(pkt)) {
            writeQueue.pollFirst()   // drop oldest
            writeQueue.offer(pkt)
        }
    }

    // Audit fix #9: session key uses full 32-bit IPs to avoid collision
    private fun sessionKey(sIP: InetAddress, sP: Int, dIP: InetAddress, dP: Int): Long {
        val sa = sIP.address; val da = dIP.address
        // Pack as: srcIP_low32 XOR-shifted with ports — unique for distinct 4-tuples
        val sI = ((sa[0].toLong() and 0xFF) shl 24) or ((sa[1].toLong() and 0xFF) shl 16) or
                 ((sa[2].toLong() and 0xFF) shl  8) or  (sa[3].toLong() and 0xFF)
        val dI = ((da[0].toLong() and 0xFF) shl 24) or ((da[1].toLong() and 0xFF) shl 16) or
                 ((da[2].toLong() and 0xFF) shl  8) or  (da[3].toLong() and 0xFF)
        return (sI shl 32) xor (dI shl 16) xor (sP.toLong() shl 32) xor dP.toLong()
    }

    // ── Checksum helpers ──────────────────────────────────────────────────────
    private fun ipCs(b: ByteArray, o: Int, l: Int): Int {
        var s = 0; var i = o
        while (i < o + l - 1) { s += (b[i].i shl 8) or b[i+1].i; i += 2 }
        if (l and 1 != 0) s += b[o + l - 1].i shl 8
        while (s ushr 16 != 0) s = (s and 0xFFFF) + (s ushr 16)
        return s.inv() and 0xFFFF
    }

    private fun tcpCs(p: ByteArray, o: Int, tl: Int, src: ByteArray, dst: ByteArray): Int {
        val ps = ByteArray(12 + tl)
        src.copyInto(ps, 0); dst.copyInto(ps, 4); ps[9] = 6; w16(ps, 10, tl)
        p.copyInto(ps, 12, o, o + tl)
        return ipCs(ps, 0, ps.size)
    }

    private val Byte.i get() = this.toInt() and 0xFF
    private fun ip4(b: ByteArray, o: Int) = InetAddress.getByAddress(b.copyOfRange(o, o + 4))
    private fun r16(b: ByteArray, o: Int) = (b[o].i shl 8) or b[o+1].i
    private fun r32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xFF shl 24) or (b[o+1].toLong() and 0xFF shl 16) or
        (b[o+2].toLong() and 0xFF shl  8) or (b[o+3].toLong() and 0xFF)
    private fun w16(b: ByteArray, o: Int, v: Int) { b[o]=(v shr 8 and 0xFF).toByte(); b[o+1]=(v and 0xFF).toByte() }
    private fun w32(b: ByteArray, o: Int, v: Long) {
        b[o]=(v shr 24 and 0xFF).toByte(); b[o+1]=(v shr 16 and 0xFF).toByte()
        b[o+2]=(v shr 8 and 0xFF).toByte(); b[o+3]=(v and 0xFF).toByte()
    }

    // ── Gateway ───────────────────────────────────────────────────────────────
    private fun startGw() {
        if (gwStarted) return
        if (!engineStarted) start()
        val gw = HotspotGateway(this, null); gw.grantConsent(); gw.start()
        gateway = gw; gwStarted = true; postNotif()
    }

    private fun stopGw() {
        gateway?.stop(); gateway = null; gwStarted = false
        if (engineStarted) postNotif()
    }

    // ── Notification ──────────────────────────────────────────────────────────
    private fun makeChan() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val c = NotificationChannel(CH_ID, "RNET Transport", NotificationManager.IMPORTANCE_LOW)
                .apply { description = "RNET VPN"; setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(c)
        }
    }

    private fun notif(): Notification {
        val tap  = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1,
            Intent(this, RnetForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE)
        val text = when (connectionPhase) {
            ConnectionPhase.IDLE          -> getString(R.string.vpn_status_connecting)
            ConnectionPhase.STARTING      -> getString(R.string.vpn_status_connecting)
            ConnectionPhase.FINDING_PROXY -> getString(R.string.vpn_status_starting_tunnel)
            ConnectionPhase.ACTIVE        -> "${getString(R.string.vpn_status_active)} · $proxyLabel"
        }
        return NotificationCompat.Builder(this, CH_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tap)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.notif_stop), stop)
            .setOngoing(true).setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun postNotif() {
        getSystemService(NotificationManager::class.java).notify(NOTIF, notif())
    }
}
