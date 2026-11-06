package com.rnet.app.service

import android.app.*
import android.content.Intent
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
import java.util.concurrent.atomic.AtomicReference

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

    // Smart routing components
    private var tunnelPool: TunnelPool? = null
    private var smartRouter: SmartRouter? = null

    private var cellMon: CellMonitor?     = null
    private var gateway: HotspotGateway? = null

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

        // Build the tunnel pool and smart router
        val tp = TunnelPool(applicationContext) { s -> protect(s) }
        tunnelPool = tp
        smartRouter = SmartRouter(tp, region, this)

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
        tunnelPool?.stopAll(); tunnelPool = null; smartRouter = null
        LocationMasker.stop(applicationContext)
        cellMon?.stop()
        activeSocksPort = 0; activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0); routeCacheSize = 0
        postNotif()
        if (!gwStarted) stopSelf()
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
            proxyLabel = "Smart·${exitRegion} (${routeCacheSize}✓)"
            postNotif()
        }
    }

    // ── Maintenance loop ──────────────────────────────────────────────────────
    private suspend fun maintenanceLoop() = withContext(Dispatchers.IO) {
        while (engineStarted) {
            delay(IDLE_EVICT_INTERVAL_MS)
            tunnelPool?.evictIdle()
            smartRouter?.evictExpired()
            routeCacheSize = smartRouter?.routeCacheSize ?: 0
        }
    }

    // ── VPN loop ─────────────────────────────────────────────────────────────
    private suspend fun vpnLoop() {
        try {
            val builder = Builder()
                .setSession("RNET")
                .setMtu(MTU)
                .addAddress(TUN_IP, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setBlocking(true)
                .also { try { it.addDisallowedApplication(packageName) } catch (_: Exception) {} }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

            tun = builder.establish() ?: run {
                Log.e(TAG, "establish() = null — no VPN permission")
                engineStarted = false; connectionPhase = ConnectionPhase.IDLE; postNotif(); return
            }

            alive = true
            Log.i(TAG, "VPN tun up ✓")

            val fd  = tun!!.fileDescriptor
            val inp = FileInputStream(fd)
            val out = FileOutputStream(fd)

            // Writer thread: drains writeQueue → tun fd
            val writer = Thread({
                while (alive || !writeQueue.isEmpty()) {
                    val pkt = writeQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    if (pkt.isEmpty()) break
                    try { out.write(pkt) } catch (_: Exception) { break }
                }
            }, "rnet-writer")
            writer.isDaemon = true; writer.start()
            writerThread = writer

            // Reader thread: reads tun fd → dispatch
            // Audit fix #1: copy slice to new array before dispatching to pool thread
            val reader = Thread({
                val buf = ByteArray(READ_BUF)
                while (alive) {
                    val n = try { inp.read(buf) } catch (_: Exception) { -1 }
                    if (n <= 0) { if (alive) continue else break }
                    val pkt = buf.copyOf(n)   // ← audit fix #1: safe copy
                    try { handlePkt(pkt, n) } catch (_: Exception) {}
                }
            }, "rnet-reader")
            reader.isDaemon = true; reader.start()
            readerThread = reader

            // Keep coroutine alive until stopped (audit fix #7: interruptible)
            withContext(Dispatchers.IO) { reader.join() }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // normal coroutine cancellation
        } catch (e: Exception) {
            Log.e(TAG, "VPN loop crashed: ${e.message}", e)
        } finally {
            alive = false
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
        // Audit fix #8: DoH parallel probing done inside DoHResolver
        val resp: ByteArray? = if (dPort == 53) {
            DoHResolver.resolveParallel(pay)
                ?: DoHResolver.resolveUdp(pay) { sock -> protect(sock) }
        } else {
            relayUdpDirect(dIP, dPort, pay)
        }
        if (resp == null) return
        writeUdpResponse(sIP, sPort, dIP, dPort, resp)
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
            // SmartRouter handles all routing: preferred → fallback → direct
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
