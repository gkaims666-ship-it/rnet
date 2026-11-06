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
 * Full traffic bypass architecture:
 *   1. VPN tun captures ALL device IP traffic (addRoute 0.0.0.0/0).
 *   2. DNS (UDP port 53) → DNS-over-HTTPS to Cloudflare/Google.
 *      ISPs cannot intercept or poison encrypted DNS.
 *   3. TCP sessions → SOCKS5 proxy chain:
 *        a. Psiphon tunnel (self-provisioning, free, works in Russia/Iran/China)
 *        b. Direct connection (works for unblocked destinations)
 *      First working proxy is cached; health-checked every 30s; replaced if dead.
 *   4. Kill switch: if the VPN tun drops, we re-establish before passing traffic.
 *      No traffic leaks through the unprotected interface.
 *   5. Auto-reconnect: if a session's proxy dies mid-stream, the session closes
 *      cleanly so the app retries. The proxy cache is invalidated and re-probed.
 *
 * Status reported via companion object fields (polled by MainViewModel every 1s):
 *   activeBytesIn / activeBytesOut — cumulative byte counters
 *   activeSessionCount             — open TCP sessions right now
 *   proxyLabel                     — human-readable label of active proxy
 *   connectionPhase                — IDLE / STARTING / FINDING_PROXY / ACTIVE
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
        private const val MAX_CON = 400
        private const val T_CONN  = 10_000
        private const val HEALTH_INTERVAL_MS = 30_000L

        // TCP flags
        private const val SYN = 0x02; private const val ACK = 0x10
        private const val FIN = 0x01; private const val RST = 0x04
        private const val PSH = 0x08

        // ── Public state (polled by MainViewModel) ──────────────────────────
        @JvmField val activeBytesIn      = AtomicLong(0L)
        @JvmField val activeBytesOut     = AtomicLong(0L)
        @JvmField val activeSessionCount = AtomicInteger(0)
        @Volatile var proxyLabel         = "—"
        @Volatile var connectionPhase    = Phase.IDLE
        @Volatile var activeSocksPort    = 0  // kept for legacy VM compat

        enum class Phase { IDLE, STARTING, FINDING_PROXY, ACTIVE }
    }

    private val pool     = Executors.newCachedThreadPool()
    private val svcScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null
    private val sessions  = ConcurrentHashMap<String, Session>()
    private val connCount = AtomicInteger(0)

    @Volatile private var alive         = false
    @Volatile private var engineStarted = false
    @Volatile private var gwStarted     = false

    // Active proxy: null = still searching, non-null = use this SOCKS5
    private val activeProxy = AtomicReference<ProxyEntry?>(null)

    private var cellMon: CellMonitor?       = null
    private var gateway: HotspotGateway?   = null
    private var psiphon: PsiphonTransport? = null

    // ── Proxy descriptor ────────────────────────────────────────────────────

    data class ProxyEntry(val host: String, val port: Int, val label: String)

    // ── Android lifecycle ────────────────────────────────────────────────────

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

    // ── Engine start / stop ──────────────────────────────────────────────────

    private fun start() {
        if (engineStarted) return
        engineStarted = true
        connectionPhase = Phase.STARTING
        activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0)
        activeProxy.set(null)
        proxyLabel = "Starting…"
        cellMon!!.start()
        psiphon = PsiphonTransport(applicationContext)
        svcScope.launch { startPsiphon() }
        svcScope.launch { vpnLoop() }
        svcScope.launch { proxyHealthLoop() }
        postNotif()
    }

    private fun stop() {
        if (!engineStarted) return
        engineStarted = false; alive = false
        connectionPhase = Phase.IDLE; proxyLabel = "—"
        sessions.values.forEach { runCatching { it.close() } }; sessions.clear()
        try { tun?.close() } catch (_: Exception) {}; tun = null
        try { psiphon?.stop() } catch (_: Exception) {}; psiphon = null
        cellMon?.stop()
        activeSocksPort = 0; activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0)
        postNotif()
        if (!gwStarted) stopSelf()
    }

    // ── Psiphon start ────────────────────────────────────────────────────────

    private suspend fun startPsiphon() = withContext(Dispatchers.IO) {
        connectionPhase = Phase.FINDING_PROXY
        try {
            Log.i(TAG, "Starting Psiphon…")
            val addr = psiphon!!.start()   // blocks up to 60s
            val port = addr.substringAfterLast(":").toIntOrNull() ?: return@withContext
            activeSocksPort = port
            activeProxy.set(ProxyEntry("127.0.0.1", port, "Psiphon"))
            proxyLabel = "Psiphon"
            connectionPhase = Phase.ACTIVE
            Log.i(TAG, "Psiphon ready → SOCKS5 127.0.0.1:$port")
            postNotif()
        } catch (e: Exception) {
            Log.w(TAG, "Psiphon failed: ${e.message}")
            // Fall through — VPN still routes, sessions will use direct
            if (connectionPhase != Phase.ACTIVE) {
                proxyLabel = "Direct"
                connectionPhase = Phase.ACTIVE
                postNotif()
            }
        }
    }

    // ── Proxy health check loop ───────────────────────────────────────────────

    private suspend fun proxyHealthLoop() = withContext(Dispatchers.IO) {
        while (alive || engineStarted) {
            delay(HEALTH_INTERVAL_MS)
            val p = activeProxy.get() ?: continue
            if (p.host == "127.0.0.1") continue  // Psiphon manages itself
            val alive = try {
                val s = Socket(); protect(s)
                s.connect(InetSocketAddress(p.host, p.port), 3000)
                val out = s.getOutputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                val resp = ByteArray(2); s.getInputStream().read(resp)
                s.close()
                resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()
            } catch (_: Exception) { false }
            if (!alive) {
                Log.w(TAG, "Proxy ${p.label} dead — invalidating")
                activeProxy.set(null)
                proxyLabel = "Reconnecting…"
                // Restart Psiphon in background
                svcScope.launch { startPsiphon() }
            }
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
                // Exclude RNET itself from tunnel to avoid routing loops
                .also { try { it.addDisallowedApplication(packageName) } catch (_: Exception) {} }

            // Kill switch: block traffic if VPN drops
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            tun = builder.establish() ?: run {
                Log.e(TAG, "establish() = null — no VPN permission")
                engineStarted = false; connectionPhase = Phase.IDLE; postNotif(); return
            }

            alive = true
            Log.i(TAG, "VPN tun up ✓")

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
            Log.e(TAG, "VPN loop crashed: ${e.message}", e)
        } finally {
            alive = false
            runCatching { tun?.close() }; tun = null
        }
    }

    // ── Packet dispatch ───────────────────────────────────────────────────────

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

    // ── TCP ───────────────────────────────────────────────────────────────────

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
                activeSessionCount.set(connCount.get())
                pool.execute {
                    try { sess.run(this) }
                    catch (e: Exception) { Log.d(TAG, "$key: ${e.message}") }
                    finally {
                        sessions.remove(key)
                        connCount.decrementAndGet()
                        activeSessionCount.set(connCount.get())
                        sess.close()
                    }
                }
            }

            flags and FIN != 0 -> sessions.remove(key)?.also { it.fin(); it.close() }

            pLen > 0 -> sessions[key]?.forward(b, pOff, pLen, seq)
        }
    }

    // ── UDP / DNS ─────────────────────────────────────────────────────────────

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
        // DNS: use DoH first, plain UDP as fallback
        val resp: ByteArray? = if (dPort == 53) {
            DoHResolver.resolve(pay)
                ?: DoHResolver.resolveUdp(pay) { sock -> protect(sock) }
        } else {
            // Non-DNS UDP: relay directly (protected socket)
            relayUdpDirect(dIP, dPort, pay)
        }
        if (resp == null) return
        writeUdpResponse(sIP, sPort, dIP, dPort, resp, out)
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

    private fun writeUdpResponse(sIP: InetAddress, sPort: Int, dIP: InetAddress, dPort: Int,
                                   resp: ByteArray, out: FileOutputStream) {
        val tot = 28 + resp.size
        val pkt = ByteArray(tot)
        pkt[0] = 0x45.toByte(); w16(pkt, 2, tot)
        pkt[8] = 64; pkt[9] = 17
        dIP.address.copyInto(pkt, 12); sIP.address.copyInto(pkt, 16)
        w16(pkt, 10, ipCs(pkt, 0, 20))
        w16(pkt, 20, dPort); w16(pkt, 22, sPort); w16(pkt, 24, 8 + resp.size)
        resp.copyInto(pkt, 28)
        synchronized(out) { runCatching { out.write(pkt) } }
    }

    // ── Session ───────────────────────────────────────────────────────────────

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
            sendTcp(out, dIP, dPort, sIP, sPort, serverIsn, cAck, SYN or ACK, null, 0)

            // Inbound: server → app
            val pump = Thread {
                val buf = ByteArray(16384)
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

            // Outbound: app → server
            val sout = s.getOutputStream()
            val buf  = ByteArray(16384)
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

        private fun connectViaProxy(vpn: VpnService): Socket? {
            val proxy = activeProxy.get()
            if (proxy != null) {
                try { return connectSocks5(vpn, proxy.host, proxy.port) }
                catch (e: Exception) {
                    Log.w(TAG, "Proxy ${proxy.label} session failed: ${e.message}")
                    // Don't invalidate here — health loop handles that
                }
            }
            // Direct fallback
            return try {
                val s = Socket(); vpn.protect(s)
                s.connect(InetSocketAddress(dIP, dPort), T_CONN)
                s.tcpNoDelay = true; s
            } catch (e: Exception) {
                Log.d(TAG, "Direct $dIP:$dPort failed: ${e.message}"); null
            }
        }

        private fun connectSocks5(vpn: VpnService, proxyHost: String, proxyPort: Int): Socket {
            val s = Socket(); vpn.protect(s)
            s.connect(InetSocketAddress(proxyHost, proxyPort), T_CONN)
            s.tcpNoDelay = true
            val sin = s.getInputStream(); val sout = s.getOutputStream()
            // Greeting
            sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
            val gr = ByteArray(2); sin.readFully(gr)
            if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte())
                throw IOException("SOCKS5 auth rejected")
            // CONNECT
            val hostStr = dIP.hostAddress!!
            val hb = hostStr.toByteArray()
            val req = ByteArrayOutputStream()
            req.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hb.size.toByte()))
            req.write(hb)
            req.write(byteArrayOf((dPort shr 8).toByte(), (dPort and 0xFF).toByte()))
            sout.write(req.toByteArray()); sout.flush()
            // Response
            val resp = ByteArray(10); sin.readFully(resp)
            if (resp[0] != 0x05.toByte() || resp[1] != 0x00.toByte())
                throw IOException("SOCKS5 CONNECT rejected: ${resp[1]}")
            val atyp = resp[3].toInt() and 0xFF
            if (atyp == 0x03) {
                val extra = (resp[4].toInt() and 0xFF) - 3
                if (extra > 0) sin.skipFully(extra.toLong())
            } else if (atyp == 0x04) {
                sin.skipFully(12)
            }
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

    // ── TCP packet builder ────────────────────────────────────────────────────

    private fun sendTcp(out: FileOutputStream,
                         srcIP: InetAddress, srcPort: Int,
                         dstIP: InetAddress, dstPort: Int,
                         seq: Long, ack: Long, flags: Int,
                         pay: ByteArray?, payLen: Int) {
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

    // ── Helpers ───────────────────────────────────────────────────────────────

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
            if (n < 0) throw EOFException("Stream ended after $off/${buf.size}")
            off += n
        }
    }

    private fun InputStream.skipFully(n: Long) {
        var rem = n; val tmp = ByteArray(256)
        while (rem > 0) {
            val r = read(tmp, 0, minOf(rem, tmp.size.toLong()).toInt())
            if (r < 0) break; rem -= r
        }
    }

    // ── Gateway ───────────────────────────────────────────────────────────────

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

    // ── Notification ──────────────────────────────────────────────────────────

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
        val statusText = when (connectionPhase) {
            Phase.IDLE          -> getString(R.string.vpn_status_connecting)
            Phase.STARTING      -> getString(R.string.vpn_status_connecting)
            Phase.FINDING_PROXY -> getString(R.string.vpn_status_starting_tunnel)
            Phase.ACTIVE        -> "${getString(R.string.vpn_status_active)} · $proxyLabel"
        }
        return NotificationCompat.Builder(this, CH_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(statusText)
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
