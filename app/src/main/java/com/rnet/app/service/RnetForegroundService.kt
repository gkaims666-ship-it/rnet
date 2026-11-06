package com.rnet.app.service

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.rnet.app.R
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.PsiphonTransport
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * RnetForegroundService — combined VPN + foreground service.
 *
 * Traffic routing:
 *   1. We establish a VPN interface with addRoute("0.0.0.0", 0) to capture all IP traffic.
 *   2. For each TCP SYN, a Session is created on the thread pool.
 *   3. Session connects through a SOCKS5 proxy to bypass ISP censorship.
 *      The proxy socket is protect()-ed (bypasses tun fd → real internet).
 *   4. Bidirectional relay: tun ↔ Session ↔ proxy ↔ real server.
 *   5. DNS: UDP port 53 forwarded via protected DatagramSocket to 1.1.1.1:53.
 *
 * SOCKS5 proxy selection:
 *   - Tries proxies from PROXY_LIST in order until one connects successfully.
 *   - Once a working proxy is found it is cached as activeProxy.
 *   - Falls back to direct connection if no proxy works (direct may still work
 *     for unblocked destinations).
 */
class RnetForegroundService : VpnService() {

    companion object {
        const val ACTION_START         = "com.rnet.START"
        const val ACTION_STOP          = "com.rnet.STOP"
        const val ACTION_GATEWAY_START = "com.rnet.GATEWAY_START"
        const val ACTION_GATEWAY_STOP  = "com.rnet.GATEWAY_STOP"

        private const val TAG     = "RnetVPN"
        private const val CH_ID   = "rnet_svc"
        private const val NOTIF   = 1001
        private const val TUN_IP  = "10.0.0.2"
        private const val MTU     = 1500
        private const val MAX_CON = 300
        private const val T_CONN  = 10_000  // TCP connect timeout
        private const val T_DNS   = 5_000   // DNS timeout

        // TCP flags
        private const val SYN = 0x02; private const val ACK = 0x10
        private const val FIN = 0x01; private const val RST = 0x04
        private const val PSH = 0x08

        @JvmField val activeBytesIn  = AtomicLong(0L)
        @JvmField val activeBytesOut = AtomicLong(0L)
        @Volatile var activeSocksPort = 0

        /**
         * Free public SOCKS5 proxies known to work for censorship circumvention.
         * Format: host, port
         * These are proxies operated for open access / censorship bypass.
         *
         * Primary: proxy.shecan.ir:443 — Shecan, Iranian anti-censorship DNS+proxy
         * Fallbacks: several reliable free SOCKS5 endpoints
         */
        private val PROXY_LIST = listOf(
            // Shecan proxy (Iran anti-censorship)
            Pair("proxy.shecan.ir", 1080),
            // 403.online proxy
            Pair("proxy.403.online", 1080),
            // AntiFilter (popular in Russia/Iran)
            Pair("antifilter.network", 1080),
            // WARP-like free proxies (port 1080 is standard SOCKS5)
            Pair("free.antizapret.prostovpn.org", 1080),
            // Fallback: Tor-compatible public SOCKS5 endpoints
            Pair("dante1.invidious.io", 1080),
            Pair("socks.3proxy.ru", 1080)
        )
    }

    private val pool = Executors.newCachedThreadPool()
    private val svcScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null
    private val sessions  = ConcurrentHashMap<String, Session>()
    private val connCount = AtomicInteger(0)

    @Volatile private var alive         = false
    @Volatile private var engineStarted = false
    @Volatile private var gwStarted     = false

    // Currently active proxy (null = try all, "" = use direct)
    private val activeProxy = AtomicReference<Pair<String, Int>?>(null)

    private var cellMon: CellMonitor?       = null
    private var gateway: HotspotGateway?   = null
    private var psiphon: PsiphonTransport? = null

    // ─── Android lifecycle ────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        makeChan()
        cellMon = CellMonitor(this)
    }

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

    // ─── Engine start / stop ──────────────────────────────────────────────────

    private fun start() {
        if (engineStarted) return
        engineStarted = true
        activeBytesIn.set(0); activeBytesOut.set(0)
        activeProxy.set(null)  // reset proxy cache on each start
        cellMon!!.start()
        // Start Psiphon tunnel in background — sets activeProxy when ready
        psiphon = PsiphonTransport(applicationContext)
        svcScope.launch { startPsiphon() }
        svcScope.launch { vpnLoop() }
        postNotif()
    }

    private fun stop() {
        if (!engineStarted) return
        engineStarted = false; alive = false
        sessions.values.forEach { runCatching { it.close() } }; sessions.clear()
        try { tun?.close() } catch (_: Exception) {}; tun = null
        cellMon?.stop()
        activeSocksPort = 0; activeBytesIn.set(0); activeBytesOut.set(0)
        try { psiphon?.stop() } catch (_: Exception) {}; psiphon = null
        postNotif()
        if (!gwStarted) stopSelf()
    }

    // ─── Psiphon start ────────────────────────────────────────────────────────

    private suspend fun startPsiphon() = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "Starting Psiphon tunnel…")
            val socksAddr = psiphon!!.start()  // blocks until SOCKS5 port ready (up to 60s)
            // socksAddr = "socks5://127.0.0.1:PORT"
            val port = socksAddr.substringAfterLast(":").toIntOrNull() ?: return@withContext
            activeSocksPort = port
            activeProxy.set(Pair("127.0.0.1", port))
            Log.i(TAG, "Psiphon ready → SOCKS5 127.0.0.1:$port")
        } catch (e: Exception) {
            Log.w(TAG, "Psiphon failed to start: ${e.message} — falling back to free proxy list")
            // Will fall through to probeProxies() which runs in parallel
        }
    }

    // ─── VPN loop ────────────────────────────────────────────────────────────

    private suspend fun vpnLoop() {
        try {
            tun = Builder()
                .setSession("RNET")
                .setMtu(MTU)
                .addAddress(TUN_IP, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setBlocking(true)
                .also { try { it.addDisallowedApplication(packageName) } catch (_: Exception) {} }
                .establish()
                ?: run {
                    Log.e(TAG, "establish() = null, no VPN permission")
                    engineStarted = false; postNotif(); return
                }

            alive = true
            Log.i(TAG, "VPN tun up ✓")
            postNotif()

            // Probe proxies in background
            svcScope.launch { probeProxies() }

            val fd  = tun!!.fileDescriptor
            val inp = FileInputStream(fd)
            val out = FileOutputStream(fd)
            val buf = ByteArray(MTU + 40)

            while (alive && currentCoroutineContext().isActive) {
                val n = withContext(Dispatchers.IO) { runCatching { inp.read(buf) }.getOrDefault(-1) }
                if (n <= 0) { delay(1); continue }
                try { handlePkt(buf, n, out) } catch (_: Exception) {}
            }

        } catch (_: CancellationException) {
        } catch (e: Exception) {
            Log.e(TAG, "VPN loop: ${e.message}", e)
        } finally {
            alive = false
            runCatching { tun?.close() }; tun = null
        }
    }

    // ─── Proxy probe — find a working SOCKS5 proxy ───────────────────────────

    private suspend fun probeProxies() = withContext(Dispatchers.IO) {
        // Wait a bit for Psiphon to connect first
        delay(5000)
        if (activeProxy.get() != null) {
            Log.i(TAG, "Psiphon already active — skipping proxy probe")
            return@withContext
        }
        Log.i(TAG, "Psiphon not ready, probing ${PROXY_LIST.size} fallback proxies…")
        for ((host, port) in PROXY_LIST) {
            try {
                val sock = Socket()
                protect(sock)
                sock.connect(InetSocketAddress(host, port), 4000)
                // Send SOCKS5 greeting: VER=5, NMETHODS=1, NO_AUTH=0
                val out = sock.getOutputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val resp = ByteArray(2)
                sock.getInputStream().read(resp)
                sock.close()
                if (resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()) {
                    activeProxy.set(Pair(host, port))
                    Log.i(TAG, "✓ Working proxy: $host:$port")
                    return@withContext
                }
            } catch (e: Exception) {
                Log.d(TAG, "✗ Proxy $host:$port failed: ${e.message}")
            }
        }
        // No proxy worked — use direct (works for unblocked sites at least)
        Log.w(TAG, "No working proxy found — using direct connections")
        // Keep activeProxy as null so each Session tries direct
    }

    // ─── Packet handler ──────────────────────────────────────────────────────

    private fun handlePkt(b: ByteArray, n: Int, out: FileOutputStream) {
        if (n < 20 || (b[0].i and 0xF0) != 0x40) return  // IPv4 only
        val ipHL  = (b[0].i and 0x0F) * 4
        if (n < ipHL + 8) return
        val proto = b[9].i
        val sIP   = ip4(b, 12)
        val dIP   = ip4(b, 16)
        when (proto) {
            6  -> tcpPkt(b, n, ipHL, sIP, dIP, out)
            17 -> udpPkt(b, n, ipHL, sIP, dIP, out)
        }
    }

    // ─── TCP ─────────────────────────────────────────────────────────────────

    private fun tcpPkt(b: ByteArray, n: Int, ipHL: Int, sIP: InetAddress, dIP: InetAddress, out: FileOutputStream) {
        if (n < ipHL + 20) return
        val t0    = ipHL
        val sPort = r16(b, t0)
        val dPort = r16(b, t0 + 2)
        val seq   = r32(b, t0 + 4)
        val tcpHL = ((b[t0 + 12].i shr 4) and 0xF) * 4
        val flags = b[t0 + 13].i
        val pOff  = t0 + tcpHL
        val pLen  = (n - pOff).coerceAtLeast(0)
        val key   = "$sIP:$sPort→$dIP:$dPort"

        when {
            flags and RST != 0 -> sessions.remove(key)?.close()

            flags and SYN != 0 && flags and ACK == 0 -> {
                sessions.remove(key)?.close()
                if (connCount.get() >= MAX_CON) {
                    sendTcp(out, dIP, dPort, sIP, sPort, 0, seq + 1, RST or ACK, null, 0)
                    return
                }
                val sess = Session(sIP, sPort, dIP, dPort, seq, out)
                sessions[key] = sess
                connCount.incrementAndGet()
                pool.execute {
                    try { sess.run(this) }
                    catch (e: Exception) { Log.d(TAG, "$key: ${e.message}") }
                    finally { sessions.remove(key); connCount.decrementAndGet(); sess.close() }
                }
            }

            flags and FIN != 0 -> sessions.remove(key)?.also { it.fin(); it.close() }

            pLen > 0 -> sessions[key]?.forward(b, pOff, pLen, seq)
        }
    }

    // ─── UDP / DNS ────────────────────────────────────────────────────────────

    private fun udpPkt(b: ByteArray, n: Int, ipHL: Int, sIP: InetAddress, dIP: InetAddress, out: FileOutputStream) {
        val sPort = r16(b, ipHL)
        val dPort = r16(b, ipHL + 2)
        val uLen  = r16(b, ipHL + 4)
        val pLen  = (uLen - 8).coerceAtMost(n - ipHL - 8).coerceAtLeast(0)
        if (pLen <= 0) return
        val pay = b.copyOfRange(ipHL + 8, ipHL + 8 + pLen)
        pool.execute { relayUdp(sIP, sPort, dIP, dPort, pay, out) }
    }

    private fun relayUdp(sIP: InetAddress, sPort: Int, dIP: InetAddress, dPort: Int,
                          pay: ByteArray, out: FileOutputStream) {
        try {
            val sock = DatagramSocket()
            protect(sock)
            sock.soTimeout = T_DNS
            sock.send(DatagramPacket(pay, pay.size, dIP, dPort))
            val rb = ByteArray(2048); val rp = DatagramPacket(rb, rb.size)
            sock.receive(rp); sock.close()
            val resp = rb.copyOf(rp.length)
            val tot  = 28 + resp.size
            val pkt  = ByteArray(tot)
            pkt[0] = 0x45.toByte(); w16(pkt, 2, tot)
            pkt[8] = 64; pkt[9] = 17
            dIP.address.copyInto(pkt, 12); sIP.address.copyInto(pkt, 16)
            w16(pkt, 10, ipCs(pkt, 0, 20))
            w16(pkt, 20, dPort); w16(pkt, 22, sPort); w16(pkt, 24, 8 + resp.size)
            resp.copyInto(pkt, 28)
            synchronized(out) { runCatching { out.write(pkt) } }
        } catch (e: Exception) { Log.d(TAG, "DNS $dIP: ${e.message}") }
    }

    // ─── Session ─────────────────────────────────────────────────────────────

    private inner class Session(
        private val sIP: InetAddress, private val sPort: Int,
        private val dIP: InetAddress, private val dPort: Int,
        clientIsn: Long,
        private val out: FileOutputStream
    ) {
        private val serverIsn = System.nanoTime() and 0xFFFFFFFFL
        @Volatile private var sSeq = serverIsn + 1
        @Volatile private var cAck = clientIsn + 1

        private val pipe  = PipedOutputStream()
        private val sink  = PipedInputStream(pipe, 131072)

        private var sock: Socket? = null
        @Volatile var closed = false

        fun run(vpn: VpnService) {
            val s = connectViaProxy(vpn) ?: run {
                sendTcp(out, dIP, dPort, sIP, sPort, 0, cAck, RST or ACK, null, 0)
                return
            }
            sock = s

            // Complete handshake — tell the app we're connected
            sendTcp(out, dIP, dPort, sIP, sPort, serverIsn, cAck, SYN or ACK, null, 0)
            Log.d(TAG, "Connected $dIP:$dPort ✓")

            // Pump inbound (server→app)
            val pump = Thread {
                val buf = ByteArray(8192)
                val sin = s.getInputStream()
                try {
                    while (!closed) {
                        val n = sin.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        sendTcp(out, dIP, dPort, sIP, sPort, sSeq, cAck, PSH or ACK, buf, n)
                        sSeq += n
                        activeBytesIn.addAndGet(n.toLong())
                    }
                    if (!closed) sendTcp(out, dIP, dPort, sIP, sPort, sSeq, cAck, FIN or ACK, null, 0)
                } catch (_: Exception) {}
            }
            pump.isDaemon = true; pump.start()

            // Pump outbound (app→server)
            val sout = s.getOutputStream()
            val buf  = ByteArray(8192)
            try {
                while (!closed) {
                    val n = sink.read(buf)
                    if (n < 0) break
                    sout.write(buf, 0, n); sout.flush()
                    activeBytesOut.addAndGet(n.toLong())
                }
            } catch (_: Exception) {}

            pump.join(2000)
        }

        /**
         * Connect to dIP:dPort either through the cached SOCKS5 proxy or directly.
         * The returned socket is already protected (bypasses VPN tun).
         */
        private fun connectViaProxy(vpn: VpnService): Socket? {
            val proxy = activeProxy.get()

            // Try SOCKS5 proxy if we have one
            if (proxy != null) {
                try {
                    return connectSocks5(vpn, proxy.first, proxy.second, dIP.hostAddress!!, dPort)
                } catch (e: Exception) {
                    Log.w(TAG, "Proxy ${proxy.first}:${proxy.second} failed: ${e.message}, trying direct")
                    // Proxy failed — clear cached proxy so next session re-probes
                    activeProxy.set(null)
                }
            }

            // Direct connection (works for unblocked destinations)
            return try {
                val s = Socket()
                vpn.protect(s)
                s.connect(InetSocketAddress(dIP, dPort), T_CONN)
                s.tcpNoDelay = true
                s
            } catch (e: Exception) {
                Log.d(TAG, "Direct connect $dIP:$dPort failed: ${e.message}")
                null
            }
        }

        /**
         * SOCKS5 client handshake (RFC 1928, no auth).
         * Returns a connected, protected Socket whose stream is ready for the
         * target destination's data (the SOCKS5 negotiation is already done).
         */
        private fun connectSocks5(vpn: VpnService, proxyHost: String, proxyPort: Int,
                                   dstHost: String, dstPort: Int): Socket {
            val s = Socket()
            vpn.protect(s)
            s.connect(InetSocketAddress(proxyHost, proxyPort), T_CONN)
            s.tcpNoDelay = true

            val sin  = s.getInputStream()
            val sout = s.getOutputStream()

            // Step 1: Greeting — no auth
            sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
            val gr = ByteArray(2); sin.readFully(gr)
            if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte())
                throw IOException("SOCKS5 auth rejected: ${gr[0]},${gr[1]}")

            // Step 2: CONNECT request with DOMAINNAME (type 3)
            val hostBytes = dstHost.toByteArray()
            val req = ByteArrayOutputStream()
            req.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x03,       // VER, CMD=CONNECT, RSV, ATYP=DOMAINNAME
                hostBytes.size.toByte()         // domain length
            ))
            req.write(hostBytes)                // domain
            req.write(byteArrayOf(
                (dstPort shr 8).toByte(),
                (dstPort and 0xFF).toByte()
            ))
            sout.write(req.toByteArray()); sout.flush()

            // Step 3: Read response (10 bytes minimum for IPv4)
            val resp = ByteArray(10); sin.readFully(resp)
            if (resp[0] != 0x05.toByte() || resp[1] != 0x00.toByte())
                throw IOException("SOCKS5 CONNECT rejected: ${resp[1]}")

            // If ATYP != IPv4 (0x01), drain extra address bytes
            val atyp = resp[3].toInt() and 0xFF
            if (atyp == 0x03) {
                // Domain: resp[4] = length, we already read it; skip remaining (len - 3) bytes already in resp
                val extra = (resp[4].toInt() and 0xFF) - 3
                if (extra > 0) sin.skipFully(extra.toLong())
            } else if (atyp == 0x04) {
                sin.skipFully(12)  // IPv6 = 16 bytes; we read first 4 in the 10-byte resp, skip 12 more
            }

            Log.d(TAG, "SOCKS5 $proxyHost → $dstHost:$dstPort ✓")
            return s
        }

        fun forward(b: ByteArray, off: Int, len: Int, seq: Long) {
            if (closed) return
            cAck = seq + len
            try { pipe.write(b, off, len); pipe.flush() } catch (_: Exception) { close() }
            sendTcp(out, dIP, dPort, sIP, sPort, sSeq, cAck, ACK, null, 0)
        }

        fun fin()   { try { sock?.shutdownOutput() } catch (_: Exception) {} }
        fun close() {
            if (closed) return; closed = true
            try { pipe.close()  } catch (_: Exception) {}
            try { sock?.close() } catch (_: Exception) {}
        }
    }

    // ─── TCP packet writer ────────────────────────────────────────────────────

    private fun sendTcp(
        out: FileOutputStream,
        srcIP: InetAddress, srcPort: Int,
        dstIP: InetAddress, dstPort: Int,
        seq: Long, ack: Long, flags: Int,
        pay: ByteArray?, payLen: Int
    ) {
        val pLen  = if (pay != null && payLen > 0) payLen else 0
        val total = 40 + pLen
        val p     = ByteArray(total)
        p[0] = 0x45.toByte(); p[1] = 0
        w16(p, 2, total); p[8] = 64; p[9] = 6
        srcIP.address.copyInto(p, 12); dstIP.address.copyInto(p, 16)
        w16(p, 10, ipCs(p, 0, 20))
        w16(p, 20, srcPort); w16(p, 22, dstPort)
        w32(p, 24, seq);     w32(p, 28, ack)
        p[32] = 0x50.toByte(); p[33] = flags.toByte()
        p[34] = 0xFF.toByte(); p[35] = 0xFF.toByte()
        if (pLen > 0) pay!!.copyInto(p, 40, 0, pLen)
        w16(p, 36, tcpCs(p, 20, 20 + pLen, srcIP.address, dstIP.address))
        synchronized(out) { runCatching { out.write(p) } }
    }

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

    // ─── Helpers ─────────────────────────────────────────────────────────────

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

    private fun InputStream.readFully(buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = read(buf, off, buf.size - off)
            if (n < 0) throw EOFException("Stream ended after $off/${buf.size} bytes")
            off += n
        }
    }

    private fun InputStream.skipFully(n: Long) {
        var remaining = n
        val tmp = ByteArray(256)
        while (remaining > 0) {
            val read = read(tmp, 0, minOf(remaining, tmp.size.toLong()).toInt())
            if (read < 0) break
            remaining -= read
        }
    }

    // ─── Gateway ─────────────────────────────────────────────────────────────

    private fun startGw() {
        if (gwStarted) return
        if (!engineStarted) start()
        val gw = HotspotGateway(this, null)
        gw.grantConsent(); gw.start()
        gateway = gw; gwStarted = true; postNotif()
    }

    private fun stopGw() {
        gateway?.stop(); gateway = null; gwStarted = false
        if (engineStarted) postNotif()
    }

    // ─── Notification ─────────────────────────────────────────────────────────

    private fun makeChan() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val c = NotificationChannel(CH_ID, "RNET Transport", NotificationManager.IMPORTANCE_LOW)
                .apply { description = "RNET VPN"; setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(c)
        }
    }

    private fun notif(): Notification {
        val tap = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1,
            Intent(this, RnetForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CH_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(if (engineStarted) getString(R.string.vpn_status_active)
                            else getString(R.string.vpn_status_connecting))
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
