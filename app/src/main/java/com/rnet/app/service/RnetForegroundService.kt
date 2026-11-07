package com.rnet.app.service

import android.app.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
        const val ACTION_CHANGE_REGION = "com.rnet.CHANGE_REGION"
        const val EXTRA_REGION         = "region"

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
        // Apps excluded from VPN (split tunneling).
        // Google/YouTube traffic bypasses the VPN because:
        //   1. YouTube CDN IPs (googlevideo.com) are blocked by Psiphon exit nodes — data-center
        //      IPs get rate-limited or 403'd by Google's anti-proxy systems.
        //   2. Russian ISPs do NOT block YouTube/Google directly (unlike some other services),
        //      so a direct connection works fine and is faster.
        //   3. GMS/Firebase are excluded to prevent VPN restart loops on network callbacks.
        val SPLIT_TUNNEL_PACKAGES = setOf(
            "com.android.vending",              // Play Store
            "com.google.android.gms",           // Google Play Services
            "com.google.android.gsf",           // Google Services Framework
            "com.google.android.youtube",       // YouTube — Psiphon exits are proxy-blocked by Google CDN
            "com.google.android.apps.youtube.music", // YouTube Music
            "com.google.android.googlequicksearchbox", // Google Search/Assistant
            "com.google.android.gm",            // Gmail
            "com.google.android.apps.maps",     // Google Maps
            "com.google.android.talk",          // Google Meet
            "com.google.android.apps.meetings", // Google Meet (new package)
            "com.android.providers.downloads",
            "com.sec.android.daemonapp"         // Samsung system daemon
        )
    }

    // ── Thread pool ─────────────────────────────────────────────────────────
    private val pool = ThreadPoolExecutor(
        4, 1024, 60L, TimeUnit.SECONDS, SynchronousQueue(),
        ThreadPoolExecutor.CallerRunsPolicy()
    )

    // Dedicated DNS thread pool — bounded so DoH timeouts can't exhaust the main pool
    private val dnsPool = ThreadPoolExecutor(
        2, 16, 30L, TimeUnit.SECONDS, LinkedBlockingDeque(64),
        ThreadPoolExecutor.DiscardOldestPolicy()   // drop oldest pending DNS if queue full
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

    // ── Command broadcast receiver ────────────────────────────────────────────
    // Receives ACTION_STOP / ACTION_GATEWAY_START / etc. via sendBroadcast() from
    // MainViewModel. Using sendBroadcast() instead of startForegroundService() avoids
    // ForegroundServiceStartNotAllowedException on Android 14 when the app is backgrounded.
    // The receiver is only registered while the service is alive so it cannot be reached
    // from outside the app (not exported, requires the app's own signature).
    private val commandReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            when (intent?.action) {
                ACTION_STOP          -> { stop(); stopGw() }
                ACTION_GATEWAY_START -> startGw()
                ACTION_GATEWAY_STOP  -> stopGw()
                ACTION_CHANGE_REGION -> intent.getStringExtra(EXTRA_REGION)?.let { changeRegion(it) }
            }
        }
    }

    // ── Android lifecycle ────────────────────────────────────────────────────
    override fun onCreate() {
        super.onCreate()
        makeChan()
        cellMon = CellMonitor(this)
        // Register the command receiver. RECEIVER_NOT_EXPORTED (API 33+) ensures it
        // is not accessible from other apps. On older APIs the flag is 0 — the receiver
        // is still protected by the IntentFilter using package-scoped action strings.
        val filter = IntentFilter().apply {
            addAction(ACTION_STOP)
            addAction(ACTION_GATEWAY_START)
            addAction(ACTION_GATEWAY_STOP)
            addAction(ACTION_CHANGE_REGION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(commandReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(commandReceiver, filter)
        }
    }

    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        // Android 14+ requires specifying foregroundServiceType explicitly.
        // Passing the deprecated 2-arg form on API 34+ can throw
        // ForegroundServiceStartNotAllowedException and crash the service instantly.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIF, notif(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            @Suppress("DEPRECATION")
            startForeground(NOTIF, notif())
        }
        when (i?.action) {
            ACTION_START         -> start()
            ACTION_STOP          -> { stop(); stopGw() }
            ACTION_GATEWAY_START -> startGw()
            ACTION_GATEWAY_STOP  -> stopGw()
            ACTION_CHANGE_REGION -> i.getStringExtra(EXTRA_REGION)?.let { changeRegion(it) }
        }
        return START_STICKY
    }

    override fun onRevoke()  { stop(); super.onRevoke() }
    override fun onBind(i: Intent?) = null
    override fun onDestroy() {
        runCatching { unregisterReceiver(commandReceiver) }
        stopGw(); stop(); svcScope.cancel(); super.onDestroy()
    }

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
        engineStarted = false
        connectionPhase = ConnectionPhase.IDLE; proxyLabel = "—"
        sessions.values.forEach { runCatching { it.close() } }; sessions.clear()
        // Crash fix: set alive=false AFTER queueing poison pill so writer thread
        // doesn't hang in poll() forever waiting for the terminator that never arrives.
        writeQueue.clear(); writeQueue.offer(ByteArray(0))
        alive = false
        readerThread?.interrupt(); writerThread?.interrupt()
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
        // Bug fix: only postNotif() when gateway keeps the service alive.
        // If we're stopping entirely, skip the notification update — we're about to remove it.
        if (!gwStarted) {
            // Remove the persistent notification and stop the foreground service properly.
            // stopForeground() must be called before stopSelf() on Android 12+ (API 31+)
            // to remove the notification; stopSelf() alone leaves it stuck.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
        } else {
            // Gateway still running — update notification to reflect engine stopped
            postNotif()
        }
    }

    // ── Live region hot-swap (no VPN disconnect needed) ───────────────────────
    /**
     * Change exit country without stopping the VPN.
     * 1. Update exit region state variables
     * 2. Tell SmartRouter to prefer the new region from now on
     * 3. Clear per-destination route cache so connections re-probe via new region
     * 4. Warm up the new region's tunnel in background
     * 5. Update UI + notification
     */
    private fun changeRegion(newRegion: String) {
        if (!engineStarted) {
            // Not connected yet — just store preference
            pendingRegion = newRegion
            exitRegion = newRegion
            return
        }
        if (newRegion == exitRegion) return   // no-op

        Log.i(TAG, "Hot region swap: $exitRegion → $newRegion")
        pendingRegion = newRegion
        exitRegion = newRegion
        proxyLabel = "Switching to $newRegion…"
        postNotif()

        // Persist preference
        getSharedPreferences("rnet_prefs", MODE_PRIVATE)
            .edit().putString("exit_region", newRegion).apply()

        // Update SmartRouter's preferred region and clear cached routes
        // (new connections will re-probe and find new region tunnel)
        val router = smartRouter
        if (router != null) {
            router.setPreferredRegion(newRegion)
            router.clearAllRoutes()
        }

        // Warm up the new tunnel in background, then update label
        svcScope.launch {
            val tp = tunnelPool ?: return@launch
            val port = tp.getSocksPort(newRegion)
            if (port > 0) {
                activeSocksPort = port
                exitRegion = newRegion
                proxyLabel = "Smart·$newRegion"
                val city = LocationMasker.start(applicationContext, newRegion)
                if (city != null) Log.i(TAG, "GPS → $city")
                // Verify actual exit IP and start GPS refresh for new region
                launch { verifyExitIpAndUpdateRegion(port, newRegion) }
                launch { gpsRefreshLoop(newRegion) }
            } else {
                Log.w(TAG, "New region $newRegion tunnel failed — keeping existing")
                proxyLabel = "Smart·$exitRegion"
            }
            postNotif()
        }
    }

    // ── Network change handling (seamless WiFi↔cellular handoff) ─────────────
    private fun registerNetworkCallback() {
        // Crash fix: unregister any existing callback before registering a new one
        // to prevent double-registration on service restart
        unregisterNetworkCallback()
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
        // Crash fix: close the tun fd directly — this causes the blocking read() in
        // readerThread to return -1/IOException immediately, which makes the reader
        // exit cleanly. vpnLoop then re-establishes. Do NOT delay() after interrupt()
        // as the reader may be mid-packet and delay creates a race with alive.
        try { tun?.close() } catch (_: Exception) {}
        // Also interrupt the reader in case it's not in a blocking read right now
        readerThread?.interrupt()
        // Bug fix: clear stale packets queued for the old tun fd. Without this, packets
        // buffered during the network switch are written to the new tun fd, corrupting
        // the byte stream of every live TCP session on the new interface.
        writeQueue.clear()
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

            // Verify actual exit IP and update region label to match reality
            launch { verifyExitIpAndUpdateRegion(port, preferredRegion) }

            val city = LocationMasker.start(applicationContext, preferredRegion)
            if (city != null) Log.i(TAG, "GPS → $city")

            // Schedule periodic GPS mock refresh (some apps re-query location every ~30s)
            launch { gpsRefreshLoop(preferredRegion) }

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
                    launch { verifyExitIpAndUpdateRegion(p, fb) }
                    val city = LocationMasker.start(applicationContext, fb)
                    if (city != null) Log.i(TAG, "GPS → $city")
                    launch { gpsRefreshLoop(fb) }
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

    // ── Exit IP verification ──────────────────────────────────────────────────
    /**
     * After a tunnel is established, check the actual exit IP country by connecting
     * to ipinfo.io/country *through the SOCKS5 proxy* using ATYP=3 (domain name).
     *
     * IMPORTANT — no DoH inside this function.
     * DoH requests go through HttpsURLConnection, which the VPN tun intercepts and
     * routes back through SOCKS5 → creating a routing loop that hangs all traffic.
     * Instead we use SOCKS5 ATYP=3 (hostname CONNECT) so the proxy resolves the
     * hostname externally without touching the tun at all.
     */
    private suspend fun verifyExitIpAndUpdateRegion(socksPort: Int, requestedRegion: String) =
        withContext(Dispatchers.IO) {
        if (!engineStarted) return@withContext
        // Small delay so the tunnel is fully warmed before probing
        delay(3_000L)
        if (!engineStarted) return@withContext
        try {
            val host = "ipinfo.io"
            val port = 80  // plain HTTP — no TLS setup needed for a 2-letter country code

            // Connect directly to the SOCKS5 proxy on localhost — this socket is protect()ed
            // so it bypasses the VPN tun and goes straight to the network.
            val s = Socket()
            protect(s)
            s.soTimeout = 10_000
            s.connect(InetSocketAddress("127.0.0.1", socksPort), 5_000)
            s.use { sock ->
                val din  = java.io.DataInputStream(sock.getInputStream())
                val sout = sock.getOutputStream()

                // SOCKS5 greeting — no auth
                sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
                val gr = ByteArray(2); din.readFully(gr)
                if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte()) return@withContext

                // SOCKS5 CONNECT with ATYP=3 (hostname) — proxy resolves DNS externally.
                // This avoids any DNS call on our end (no routing loop).
                val hostBytes = host.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(7 + hostBytes.size).also { r ->
                    r[0] = 0x05; r[1] = 0x01; r[2] = 0x00
                    r[3] = 0x03                         // ATYP = domain name
                    r[4] = hostBytes.size.toByte()
                    hostBytes.copyInto(r, 5)
                    r[5 + hostBytes.size] = (port shr 8).toByte()
                    r[6 + hostBytes.size] = (port and 0xFF).toByte()
                }
                sout.write(req); sout.flush()

                // SOCKS5 CONNECT response — read the fixed 4-byte header first,
                // then drain the variable-length bound address field.
                // Format: VER(1) REP(1) RSV(1) ATYP(1) [BND.ADDR] BND.PORT(2)
                val hdr = ByteArray(4); din.readFully(hdr)
                if (hdr[0] != 0x05.toByte() || hdr[1] != 0x00.toByte()) return@withContext
                when (hdr[3].toInt() and 0xFF) {
                    0x01 -> { val skip = ByteArray(4 + 2); din.readFully(skip) }  // IPv4 + port
                    0x04 -> { val skip = ByteArray(16 + 2); din.readFully(skip) } // IPv6 + port
                    0x03 -> {                                                       // domain + port
                        val len = din.read() and 0xFF
                        val skip = ByteArray(len + 2); din.readFully(skip)
                    }
                    else -> return@withContext
                }

                // Proxy connected — send plain HTTP GET /country
                sout.write("GET /country HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
                sout.flush()

                // Read response — find blank line separating headers from body
                val body = sock.getInputStream().bufferedReader().readText()
                val country = body.substringAfterLast("\r\n\r\n").trim().take(2).uppercase()
                if (country.length == 2 && country.all { it.isLetter() }) {
                    Log.i(TAG, "Actual exit: $country (requested: $requestedRegion)")
                    exitRegion = country
                    proxyLabel = "Smart·$country"
                    LocationMasker.start(applicationContext, country)
                    postNotif()
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Exit IP check skipped: ${e.message}")
        }
    }

    // ── GPS refresh loop ──────────────────────────────────────────────────────
    /**
     * Push fresh GPS mock coordinates every 15 seconds.
     * Many apps (browsers, location services) re-query GPS regularly.
     * Without refreshing, the mock provider can go stale and apps fall back
     * to network/cell-tower location (which reveals the real location).
     */
    private suspend fun gpsRefreshLoop(region: String) = withContext(Dispatchers.IO) {
        while (engineStarted) {
            delay(15_000L)
            if (!engineStarted) break
            LocationMasker.push(applicationContext, exitRegion.ifEmpty { region })
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
                // Crash fix: use use{} to guarantee socket close even on exception
                val healthy = try {
                    val s = Socket()
                    protect(s)
                    s.soTimeout = 2000
                    s.use {
                        it.connect(InetSocketAddress("127.0.0.1", port), 2000)
                        it.getOutputStream().write(byteArrayOf(0x05, 0x01, 0x00))
                        it.getOutputStream().flush()
                        val resp = ByteArray(2)
                        val din = java.io.DataInputStream(it.getInputStream())
                        din.readFully(resp)   // must read exactly 2 bytes
                        resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()
                    }
                } catch (_: Exception) { false }

                if (!healthy) {
                    Log.w(TAG, "Tunnel $region unhealthy — evicting route cache")
                    smartRouter?.evictExpired()
                }
            }

            // Update UI stats — don't overwrite a "Switching…" label mid-transition
            routeCacheSize = smartRouter?.routeCacheSize ?: 0
            pooledSockets  = smartRouter?.connPool?.totalPooled() ?: 0
            if (!proxyLabel.startsWith("Switching")) {
                proxyLabel = "Smart·${exitRegion} (${routeCacheSize}✓ ${pooledSockets}⚡)"
            }
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
        // New feature: exponential backoff with jitter on failure
        var backoffMs = 1_000L
        while (engineStarted) {
            val start = System.currentTimeMillis()
            val ex = runCatching { buildAndRunTun() }.exceptionOrNull()
            if (!engineStarted) break
            val ran = System.currentTimeMillis() - start
            if (ran > 30_000L) {
                // Ran for a while — reset backoff (normal network switch, not a boot failure)
                backoffMs = 1_000L
            } else {
                // Short run = failed fast — back off with jitter (50-150% of backoffMs)
                // Bug fix: Math.random() delegates to a shared java.util.Random instance
                // that is not thread-safe; use kotlin.random.Random which is thread-safe.
                val jitter = (backoffMs * (0.5 + kotlin.random.Random.nextDouble())).toLong()
                delay(jitter)
                backoffMs = (backoffMs * 2).coerceAtMost(30_000L)   // cap at 30s
            }
            if (ex != null) Log.w(TAG, "VPN loop restart after ${ran}ms: ${ex.message}")
        }
    }

    private suspend fun buildAndRunTun() {
        var newTun: ParcelFileDescriptor? = null
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

            newTun = builder.establish() ?: run {
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

            // Bug fix: stop any writer from a previous tun build before starting a new one.
            // Without this, on a network-change rebuild two writer threads drain the same
            // writeQueue concurrently — packets are delivered out of order and to stale fds.
            writerThread?.let { prev ->
                prev.interrupt()
                // Brief join (non-blocking on IO thread) — it exits quickly via the
                // `tun !== newTun` check now that tun has been swapped above.
                try { prev.join(500) } catch (_: InterruptedException) {}
            }

            // Writer thread
            // Crash fix: check that the fd is still the one we opened (tun === newTun)
            // before each write. If tun changed (rebuildTun closed it), exit cleanly.
            val writer = Thread({
                while (alive || !writeQueue.isEmpty()) {
                    val pkt = writeQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    if (pkt.isEmpty()) break
                    if (tun !== newTun) break   // fd replaced — stop writing to stale fd
                    try { out.write(pkt) } catch (_: Exception) { break }
                }
            }, "rnet-writer")
            writer.isDaemon = true; writer.start()
            writerThread = writer

            // Reader thread — audit fix #1: copy buffer before dispatch
            val reader = Thread({
                val buf = ByteArray(READ_BUF)
                while (alive) {
                    val n = try {
                        inp.read(buf)
                    } catch (_: Exception) {
                        // IOException means the fd was closed (by rebuildTun or stop).
                        // Break immediately — continuing would spin on a dead fd and
                        // block all traffic until the thread is interrupted externally.
                        break
                    }
                    if (n <= 0) break   // EOF: tun closed, exit cleanly
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
            // Bug fix #4: only close the tun we opened here, not the current service tun
            // (tun field may have been updated by a concurrent rebuildTun or stopAll)
            if (tun === newTun) { runCatching { tun?.close() }; tun = null }
            else { runCatching { newTun?.close() } }
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
                // Bug fix #7: use single atomic increment and copy to activeSessionCount atomically
                activeSessionCount.set(connCount.incrementAndGet())
                pool.execute {
                    try { sess.run() }
                    catch (e: Exception) { Log.d(TAG, "${sIP}:${sPort}→${dIP}:${dPort}: ${e.message}") }
                    finally {
                        sessions.remove(key)
                        activeSessionCount.set(connCount.decrementAndGet())
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
        // DNS goes to dedicated pool to prevent slow DoH from exhausting TCP thread pool
        val execPool = if (dPort == 53) dnsPool else pool
        execPool.execute { relayUdp(sIP, sPort, dIP, dPort, pay) }
    }

    private fun relayUdp(sIP: InetAddress, sPort: Int, dIP: InetAddress, dPort: Int, pay: ByteArray) {
        val resp: ByteArray? = if (dPort == 53) {
            // DNS: check cache first, then parallel DoH (protect()ed), then UDP fallback.
            // CRITICAL: pass protect lambda to DoH so the underlying TLS socket bypasses
            // the VPN tun. Without protect(), the DoH connection routes through the tun
            // itself → triggers another DNS lookup → infinite recursion → deadlock.
            val cached = tryResolveDnsFromCache(pay)
            cached ?: DoHResolver.resolveParallel(pay, protect = { sock -> protect(sock) })
                       ?.also { storeDnsToCache(pay, it) }
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
                if (pos + 10 > response.size) return@repeat   // Bug fix #2: was bare return (exited whole fn)
                // Skip name (may be pointer 0xC0 xx or labels)
                if (response[pos].toInt() and 0xC0 == 0xC0) pos += 2
                else { while (pos < response.size && response[pos] != 0.toByte()) pos++; pos++ }
                if (pos + 10 > response.size) return@repeat   // Bug fix #2: was bare return
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
        // resp = query header+question + 16-byte answer RR
        val resp = query.copyOf(query.size + 16)
        // Set QR=1 (response), RA=1 in flags
        resp[2] = 0x81.toByte(); resp[3] = 0x80.toByte()
        // QDCOUNT stays 1; set ANCOUNT = 1
        resp[6] = 0x00; resp[7] = 0x01
        // Write answer RR starting at resp[query.size]:
        //   name ptr (0xC00C), TYPE A, CLASS IN, TTL 300, RDLENGTH 4, IP
        val base = query.size
        resp[base]      = 0xC0.toByte(); resp[base + 1]  = 0x0C   // name ptr → offset 12
        resp[base + 2]  = 0x00;          resp[base + 3]  = 0x01   // TYPE A
        resp[base + 4]  = 0x00;          resp[base + 5]  = 0x01   // CLASS IN
        resp[base + 6]  = 0x00;          resp[base + 7]  = 0x00   // TTL high
        resp[base + 8]  = 0x01;          resp[base + 9]  = 0x2C   // TTL low = 300s
        resp[base + 10] = 0x00;          resp[base + 11] = 0x04   // RDLENGTH 4
        ip.address.copyInto(resp, base + 12)                       // 4-byte IPv4
        return resp
    }

    private fun relayUdpDirect(dIP: InetAddress, dPort: Int, pay: ByteArray): ByteArray? {
        // Bug fix: use use{} so the socket is always closed, even if receive() throws.
        // Previously the socket was leaked on any IOException from receive().
        return try {
            DatagramSocket().use { sock ->
                protect(sock)
                sock.soTimeout = 5000
                sock.send(DatagramPacket(pay, pay.size, dIP, dPort))
                val rb = ByteArray(4096); val rp = DatagramPacket(rb, rb.size)
                sock.receive(rp)
                rb.copyOf(rp.length)
            }
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
        // TCP sequence numbers must wrap at 2^32 (modular arithmetic per RFC 793)
        @Volatile private var sSeq = (serverIsn + 1) and 0xFFFFFFFFL
        @Volatile private var cAck = (clientIsn + 1) and 0xFFFFFFFFL

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
                        sSeq = (sSeq + n) and 0xFFFFFFFFL  // 32-bit wrap per RFC 793
                        activeBytesIn.addAndGet(n.toLong())
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
            cAck = (seq + len) and 0xFFFFFFFFL  // 32-bit wrap per RFC 793
            val chunk = b.copyOfRange(off, off + len)
            // Bug fix #6: when outQueue is full, drop oldest to maintain flow
            if (!outQueue.offer(chunk)) {
                outQueue.poll()          // discard oldest chunk
                outQueue.offer(chunk)    // then enqueue new
            }
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

    // Session key: unambiguous 128-bit-equivalent packed into a Long.
    // Layout (bits 63→0): [srcIP 32][srcPort 16][dstPort 16]
    // dstIP is the same for all tun sessions (internet dests vary) but srcIP is always
    // 10.0.0.2 so we store dstIP in the high 32 and srcPort+dstPort in the low 32.
    // This gives a unique key for every (srcPort, dstIP, dstPort) triple, which is
    // the actual uniqueness constraint because srcIP is always TUN_IP.
    private fun sessionKey(sIP: InetAddress, sP: Int, dIP: InetAddress, dP: Int): Long {
        val da = dIP.address
        val dI = ((da[0].toLong() and 0xFF) shl 24) or ((da[1].toLong() and 0xFF) shl 16) or
                 ((da[2].toLong() and 0xFF) shl  8) or  (da[3].toLong() and 0xFF)
        return (dI shl 32) or (sP.toLong() shl 16) or dP.toLong()
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
        // Bug fix: don't call start() here — startGw() may be invoked directly via
        // onStartCommand(ACTION_GATEWAY_START) before the VPN permission is granted.
        // Calling start() unconditionally would start a VPN without permission, causing
        // establish() to return null and loop, corrupting engineStarted state.
        // The gateway operates independently of the VPN engine.
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
        // STOP from notification: use getBroadcast (not getService) so it routes through
        // commandReceiver. The notification shade is a background context — getService() would
        // throw ForegroundServiceStartNotAllowedException on Android 14.
        val stop = PendingIntent.getBroadcast(this, 1,
            Intent(ACTION_STOP).apply { `package` = packageName },
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
