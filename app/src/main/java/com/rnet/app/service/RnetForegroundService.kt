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
import com.rnet.app.crypto.SessionCipher
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.MultipathEngine
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * RnetForegroundService — combined VPN + foreground service.
 *
 * Architecture:
 *   1. We start a local SOCKS5 proxy on 127.0.0.1:LOCAL_PROXY_PORT.
 *      Its sockets are protect()-ed so they bypass the VPN tun and reach real internet.
 *
 *   2. We establish a VPN interface with addRoute("0.0.0.0", 0) to capture all IP traffic.
 *
 *   3. We read raw IP packets from the tun fd. For each TCP SYN we see, we:
 *      a. Record the destination (dstIp:dstPort) keyed by (srcIp:srcPort)
 *      b. Send a fake SYN-ACK back to the app's kernel so the app thinks the connection
 *         is established
 *      c. When the app sends its first data bytes (the TLS ClientHello for HTTPS, or
 *         the HTTP request for plain HTTP), we open a protect()-ed Socket directly to
 *         the original destination and relay bytes bidirectionally
 *
 *   This avoids the need for a full TCP stack — we let the kernel manage TCP on both sides.
 *   We only deal with IP/TCP headers to track connection state and extract destinations.
 *
 *   DNS (UDP port 53):
 *      We read UDP packets from the tun, forward them via a protect()-ed DatagramSocket
 *      to 1.1.1.1:53, and write the response back as a UDP packet to the tun.
 *      This handles all DNS lookups including those for Instagram, etc.
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
        private const val T_CONN  = 15_000  // TCP connect timeout
        private const val T_DNS   = 5_000   // DNS timeout

        // TCP flags
        private const val SYN = 0x02; private const val ACK = 0x10
        private const val FIN = 0x01; private const val RST = 0x04
        private const val PSH = 0x08

        @JvmField val activeBytesIn  = AtomicLong(0L)
        @JvmField val activeBytesOut = AtomicLong(0L)
        @Volatile var activeSocksPort = 0
    }

    // Thread pool — one thread per active TCP session for blocking I/O
    private val pool = Executors.newCachedThreadPool()

    private val svcScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null
    private val sessions  = ConcurrentHashMap<String, Session>()
    private val connCount = AtomicInteger(0)

    @Volatile private var alive         = false
    @Volatile private var engineStarted = false
    @Volatile private var gwStarted     = false

    private var cellMon: CellMonitor?    = null
    private var engine:  MultipathEngine? = null
    private var gateway: HotspotGateway? = null

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
        cellMon!!.start()
        svcScope.launch { vpnLoop() }
        postNotif()
    }

    private fun stop() {
        if (!engineStarted) return
        engineStarted = false; alive = false
        sessions.values.forEach { runCatching { it.close() } }; sessions.clear()
        try { tun?.close() } catch (_: Exception) {}; tun = null
        engine?.let { runCatching { it.stop() } }; engine = null
        cellMon?.stop()
        activeSocksPort = 0; activeBytesIn.set(0); activeBytesOut.set(0)
        postNotif()
        if (!gwStarted) stopSelf()
    }

    // ─── VPN loop (runs in svcScope coroutine) ────────────────────────────────

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

    // ─── Packet handler ───────────────────────────────────────────────────────

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

    // ─── TCP ──────────────────────────────────────────────────────────────────

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
                // New connection — record destination, reply SYN-ACK
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

    // ─── Session ──────────────────────────────────────────────────────────────

    /**
     * One TCP session. Runs on a thread from the pool.
     *
     * Lifecycle:
     *   1. SYN received → Session created → run() called on pool thread
     *   2. run(): open protected Socket to real server → send SYN-ACK into tun
     *   3. App gets SYN-ACK → sends data (TLS handshake etc) → forward() called
     *   4. run(): pump bytes from real server back into tun as TCP data packets
     *   5. When server closes → send FIN into tun → session done
     *
     * Thread safety:
     *   forward() is called from the tun-read thread.
     *   pump() (inside run()) runs on the pool thread.
     *   We use a PipedStream pair to bridge them safely.
     */
    private inner class Session(
        private val sIP: InetAddress, private val sPort: Int,
        private val dIP: InetAddress, private val dPort: Int,
        clientIsn: Long,
        private val out: FileOutputStream
    ) {
        private val serverIsn = System.nanoTime() and 0xFFFFFFFFL
        @Volatile private var sSeq = serverIsn + 1  // next seq to send toward app
        @Volatile private var cAck = clientIsn + 1  // next byte expected from app

        // Pipe from forward() → run() thread
        private val pipe  = PipedOutputStream()
        private val sink  = PipedInputStream(pipe, 131072)  // 128 KB buffer

        private var sock: Socket? = null
        @Volatile var closed = false

        fun run(vpn: VpnService) {
            val s = Socket()
            sock  = s
            vpn.protect(s)
            try {
                s.connect(InetSocketAddress(dIP, dPort), T_CONN)
                s.tcpNoDelay = true
            } catch (e: Exception) {
                Log.d(TAG, "Connect $dIP:$dPort failed: ${e.message}")
                // Send RST to app
                sendTcp(out, dIP, dPort, sIP, sPort, 0, cAck, RST or ACK, null, 0)
                return
            }

            // Complete handshake
            sendTcp(out, dIP, dPort, sIP, sPort, serverIsn, cAck, SYN or ACK, null, 0)
            Log.d(TAG, "Connected $dIP:$dPort ✓")

            // Start a thread to read from real server and push to tun
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

            // Forward from pipe (filled by forward()) to real server
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

        /** Called from tun-read thread to forward app data to the real server. */
        fun forward(b: ByteArray, off: Int, len: Int, seq: Long) {
            if (closed) return
            cAck = seq + len
            try { pipe.write(b, off, len); pipe.flush() } catch (_: Exception) { close() }
            // ACK the data
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

    // ─── Helpers ──────────────────────────────────────────────────────────────

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

    // ─── Gateway ──────────────────────────────────────────────────────────────

    private fun startGw() {
        if (gwStarted) return
        if (!engineStarted) start()
        val gw = HotspotGateway(this, engine!!)
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
