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
import com.rnet.app.service.ConnectionPhase
import com.rnet.app.transport.DoHResolver
import com.rnet.app.transport.PsiphonTransport
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * RnetForegroundService — combined VPN + foreground service.
 *
 * Speed architecture:
 *   • One dedicated reader thread reads tun fd with 64 KB buffer — no coroutine per packet
 *   • One dedicated writer thread drains a lock-free write queue to tun fd
 *   • Sessions use ArrayBlockingQueue (no copy, no lock) instead of PipedStream
 *   • Long-encoded session keys avoid per-packet String allocation
 *   • Socket receive/send buffers set to 256 KB each
 *   • MTU 1500, read buffer 65535 (handles jumbo frames from tun)
 *
 * Traffic bypass architecture:
 *   1. VPN tun captures ALL device IP traffic (addRoute 0.0.0.0/0).
 *   2. DNS (UDP port 53) → DNS-over-HTTPS to Cloudflare/Google.
 *   3. TCP sessions → SOCKS5 → Psiphon tunnel (exit in chosen region for location masking).
 *   4. Direct fallback if Psiphon unavailable.
 *
 * Location masking:
 *   Psiphon exits in a configurable region (default: NL). Your apparent IP origin
 *   changes to that country. Set PREFERRED_REGION to any Psiphon egress code.
 *
 * Status reported via companion object fields (polled by MainViewModel every 1s).
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
        private const val MAX_CON = 600          // max concurrent TCP sessions
        private const val T_CONN  = 8_000        // connect timeout ms
        private const val HEALTH_INTERVAL_MS = 30_000L
        private const val READ_BUF  = 65535      // tun read buffer (IP max)
        private const val SOCK_BUF  = 262144     // socket SO_RCVBUF / SO_SNDBUF
        private const val SESSION_QUEUE_CAPACITY = 128  // per-session write queue

        // Psiphon exit region for location masking.
        // "NL" = Netherlands, "DE" = Germany, "US" = United States, "" = fastest available
        private const val PREFERRED_REGION = "NL"

        // TCP flags
        private const val SYN = 0x02; private const val ACK = 0x10
        private const val FIN = 0x01; private const val RST = 0x04
        private const val PSH = 0x08

        // ── Public state (polled by MainViewModel) ──────────────────────────
        @JvmField val activeBytesIn      = AtomicLong(0L)
        @JvmField val activeBytesOut     = AtomicLong(0L)
        @JvmField val activeSessionCount = AtomicInteger(0)
        @Volatile var proxyLabel         = "—"
        @Volatile var connectionPhase    = ConnectionPhase.IDLE
        @Volatile var activeSocksPort    = 0
        @Volatile var exitRegion         = PREFERRED_REGION  // shown in UI
    }

    // ── Thread pool ─────────────────────────────────────────────────────────
    // Core pool = 4 so idle threads don't waste RAM; max = 1024 for bursts
    private val pool = ThreadPoolExecutor(
        4, 1024, 60L, TimeUnit.SECONDS, SynchronousQueue(),
        ThreadPoolExecutor.CallerRunsPolicy()
    )

    private val svcScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null

    // Session table: Long key = (srcIP<<48 | srcPort<<32 | dstIP_low<<16 | dstPort)
    // Using ConcurrentHashMap<Long,Session> avoids String allocation per packet
    private val sessions  = ConcurrentHashMap<Long, Session>(1024)
    private val connCount = AtomicInteger(0)

    @Volatile private var alive         = false
    @Volatile private var engineStarted = false
    @Volatile private var gwStarted     = false

    // Single-writer queue to tun fd (avoid synchronized on every write)
    private val writeQueue = LinkedBlockingDeque<ByteArray>(4096)
    @Volatile private var writerThread: Thread? = null
    @Volatile private var readerThread: Thread? = null

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
        connectionPhase = ConnectionPhase.STARTING
        activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0)
        activeProxy.set(null)
        proxyLabel = "Starting…"
        cellMon!!.start()
        psiphon = PsiphonTransport(applicationContext, PREFERRED_REGION)
        svcScope.launch { startPsiphon() }
        svcScope.launch { vpnLoop() }
        svcScope.launch { proxyHealthLoop() }
        postNotif()
    }

    private fun stop() {
        if (!engineStarted) return
        engineStarted = false; alive = false
        connectionPhase = ConnectionPhase.IDLE; proxyLabel = "—"
        sessions.values.forEach { runCatching { it.close() } }; sessions.clear()
        readerThread?.interrupt(); writerThread?.interrupt()
        writeQueue.clear(); writeQueue.offer(ByteArray(0)) // wake writer
        try { tun?.close() } catch (_: Exception) {}; tun = null
        try { psiphon?.stop() } catch (_: Exception) {}; psiphon = null
        LocationMasker.stop(applicationContext)
        cellMon?.stop()
        activeSocksPort = 0; activeBytesIn.set(0); activeBytesOut.set(0)
        activeSessionCount.set(0)
        postNotif()
        if (!gwStarted) stopSelf()
    }

    // ── Psiphon start ────────────────────────────────────────────────────────
    private suspend fun startPsiphon() = withContext(Dispatchers.IO) {
        connectionPhase = ConnectionPhase.FINDING_PROXY
        try {
            Log.i(TAG, "Starting Psiphon (region=$PREFERRED_REGION)…")
            val addr = psiphon!!.start()   // blocks up to 60s
            val port = addr.substringAfterLast(":").toIntOrNull() ?: return@withContext
            activeSocksPort = port
            activeProxy.set(ProxyEntry("127.0.0.1", port, "Psiphon·$PREFERRED_REGION"))
            proxyLabel = if (PREFERRED_REGION.isEmpty()) "Psiphon" else "Psiphon·$PREFERRED_REGION"
            exitRegion = PREFERRED_REGION
            connectionPhase = ConnectionPhase.ACTIVE
            Log.i(TAG, "Psiphon ready → SOCKS5 127.0.0.1:$port")
            // Start GPS location masking — shows location of exit country
            val city = LocationMasker.start(applicationContext, PREFERRED_REGION)
            if (city != null) Log.i(TAG, "GPS mocked → $city")
            postNotif()
        } catch (e: Exception) {
            Log.w(TAG, "Psiphon failed: ${e.message}")
            if (connectionPhase != ConnectionPhase.ACTIVE) {
                proxyLabel = "Direct"
                connectionPhase = ConnectionPhase.ACTIVE
                postNotif()
            }
        }
    }

    // ── Proxy health check loop ───────────────────────────────────────────────
    private suspend fun proxyHealthLoop() = withContext(Dispatchers.IO) {
        while (alive || engineStarted) {
            delay(HEALTH_INTERVAL_MS)
            if (!engineStarted) break
            val p = activeProxy.get() ?: continue
            if (p.host == "127.0.0.1") continue  // Psiphon manages its own health
            val healthy = try {
                val s = Socket(); protect(s)
                s.connect(InetSocketAddress(p.host, p.port), 3000)
                val out = s.getOutputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                val resp = ByteArray(2); s.getInputStream().read(resp)
                s.close()
                resp[0] == 0x05.toByte() && resp[1] == 0x00.toByte()
            } catch (_: Exception) { false }
            if (!healthy) {
                Log.w(TAG, "Proxy ${p.label} dead — invalidating")
                activeProxy.set(null)
                proxyLabel = "Reconnecting…"
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
                .also { try { it.addDisallowedApplication(packageName) } catch (_: Exception) {} }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            tun = builder.establish() ?: run {
                Log.e(TAG, "establish() = null — no VPN permission")
                engineStarted = false; connectionPhase = ConnectionPhase.IDLE; postNotif(); return
            }

            alive = true
            Log.i(TAG, "VPN tun up ✓")

            val fd  = tun!!.fileDescriptor
            val inp = FileInputStream(fd)
            val out = FileOutputStream(fd)

            // ── Writer thread: drains writeQueue → tun fd ──────────────────
            val writer = Thread({
                while (alive || !writeQueue.isEmpty()) {
                    val pkt = writeQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    if (pkt.isEmpty()) break   // poison pill on stop()
                    try { out.write(pkt) } catch (_: Exception) { break }
                }
            }, "rnet-writer")
            writer.isDaemon = true; writer.start()
            writerThread = writer

            // ── Reader thread: reads tun fd → dispatch ─────────────────────
            val buf = ByteArray(READ_BUF)
            val reader = Thread({
                while (alive) {
                    val n = try { inp.read(buf) } catch (_: Exception) { -1 }
                    if (n <= 0) { if (alive) continue else break }
                    try { handlePkt(buf, n) } catch (_: Exception) {}
                }
            }, "rnet-reader")
            reader.isDaemon = true; reader.start()
            readerThread = reader

            // Keep coroutine alive until stopped
            reader.join()
        } catch (_: CancellationException) {
        } catch (e: Exception) {
            Log.e(TAG, "VPN loop crashed: ${e.message}", e)
        } finally {
            alive = false
            runCatching { tun?.close() }; tun = null
        }
    }

    // ── Packet dispatch ───────────────────────────────────────────────────────
    private fun handlePkt(b: ByteArray, n: Int) {
        if (n < 20 || (b[0].i and 0xF0) != 0x40) return  // IPv4 only
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
                    sendTcp(dIP, dPort, sIP, sPort, 0, seq + 1, RST or ACK, null, 0)
                    return
                }
                val sess = Session(sIP, sPort, dIP, dPort, seq)
                sessions[key] = sess
                connCount.incrementAndGet()
                activeSessionCount.set(connCount.get())
                pool.execute {
                    try { sess.run(this) }
                    catch (e: Exception) { Log.d(TAG, "${sIP}:${sPort}→${dIP}:${dPort}: ${e.message}") }
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
            DoHResolver.resolve(pay)
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
        writeQueue.offer(pkt)
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

        // Lock-free queue of byte chunks from tun → remote
        private val outQueue = ArrayBlockingQueue<ByteArray>(SESSION_QUEUE_CAPACITY)
        private val POISON   = ByteArray(0)

        private var sock: Socket? = null
        @Volatile var closed = false

        fun run(vpn: VpnService) {
            val s = connectViaProxy(vpn) ?: run {
                sendTcp(dIP, dPort, sIP, sPort, 0, cAck, RST or ACK, null, 0)
                return
            }
            sock = s
            sendTcp(dIP, dPort, sIP, sPort, serverIsn, cAck, SYN or ACK, null, 0)

            // Inbound: remote → tun (runs on current pool thread via nested execute)
            pool.execute {
                val buf = ByteArray(READ_BUF)
                val sin = s.getInputStream()
                try {
                    while (!closed) {
                        val n = sin.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        sendTcp(dIP, dPort, sIP, sPort, sSeq, cAck, PSH or ACK, buf, n)
                        sSeq += n
                        activeBytesIn.addAndGet(n.toLong())
                    }
                    if (!closed) sendTcp(dIP, dPort, sIP, sPort, sSeq, cAck, FIN or ACK, null, 0)
                } catch (_: Exception) {}
                finally { outQueue.offer(POISON) }
            }

            // Outbound: tun → remote (this thread)
            val sout = s.getOutputStream()
            try {
                while (!closed) {
                    val chunk = outQueue.poll(300, TimeUnit.MILLISECONDS) ?: continue
                    if (chunk === POISON || chunk.isEmpty()) break
                    sout.write(chunk); sout.flush()
                    activeBytesOut.addAndGet(chunk.size.toLong())
                }
            } catch (_: Exception) {}
        }

        private fun connectViaProxy(vpn: VpnService): Socket? {
            val proxy = activeProxy.get()
            if (proxy != null) {
                try { return connectSocks5(vpn, proxy.host, proxy.port) }
                catch (e: Exception) {
                    Log.w(TAG, "Proxy ${proxy.label} session failed: ${e.message}")
                }
            }
            // Direct fallback
            return try {
                val s = Socket(); vpn.protect(s)
                s.setReceiveBufferSize(SOCK_BUF)
                s.setSendBufferSize(SOCK_BUF)
                s.tcpNoDelay = true
                s.connect(InetSocketAddress(dIP, dPort), T_CONN)
                s
            } catch (e: Exception) {
                Log.d(TAG, "Direct $dIP:$dPort failed: ${e.message}"); null
            }
        }

        private fun connectSocks5(vpn: VpnService, proxyHost: String, proxyPort: Int): Socket {
            val s = Socket(); vpn.protect(s)
            s.setReceiveBufferSize(SOCK_BUF)
            s.setSendBufferSize(SOCK_BUF)
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(proxyHost, proxyPort), T_CONN)
            val sin = s.getInputStream(); val sout = s.getOutputStream()
            // Greeting
            sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
            val gr = ByteArray(2); sin.readFully(gr)
            if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte())
                throw IOException("SOCKS5 auth rejected")
            // CONNECT — send destination IP as IPv4 (ATYP=1) for speed
            val ipBytes = dIP.address
            val req = ByteArray(10)
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01
            ipBytes.copyInto(req, 4)
            req[8] = (dPort shr 8).toByte(); req[9] = (dPort and 0xFF).toByte()
            sout.write(req); sout.flush()
            // Response (always 10 bytes for IPv4)
            val resp = ByteArray(10); sin.readFully(resp)
            if (resp[0] != 0x05.toByte() || resp[1] != 0x00.toByte())
                throw IOException("SOCKS5 CONNECT rejected: ${resp[1]}")
            return s
        }

        fun forward(b: ByteArray, off: Int, len: Int, seq: Long) {
            if (closed) return
            cAck = seq + len
            val chunk = b.copyOfRange(off, off + len)
            outQueue.offer(chunk)   // non-blocking; drop if queue full (backpressure)
            sendTcp(dIP, dPort, sIP, sPort, sSeq, cAck, ACK, null, 0)
        }

        fun fin()   { try { sock?.shutdownOutput() } catch (_: Exception) {} }
        fun close() {
            if (closed) return; closed = true
            outQueue.offer(POISON)
            try { sock?.close() } catch (_: Exception) {}
        }
    }

    // ── TCP packet builder ────────────────────────────────────────────────────
    private fun sendTcp(srcIP: InetAddress, srcPort: Int,
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
        writeQueue.offer(p)   // non-blocking write to tun writer thread
    }

    // ── Session key ───────────────────────────────────────────────────────────
    // Packs (srcIP_low16 << 48 | srcPort << 32 | dstIP_low16 << 16 | dstPort) into Long
    // Avoids String allocation on every packet
    private fun sessionKey(sIP: InetAddress, sP: Int, dIP: InetAddress, dP: Int): Long {
        val sa = sIP.address; val da = dIP.address
        val sLow = ((sa[2].toLong() and 0xFF) shl 8) or (sa[3].toLong() and 0xFF)
        val dLow = ((da[2].toLong() and 0xFF) shl 8) or (da[3].toLong() and 0xFF)
        return (sLow shl 48) or (sP.toLong() shl 32) or (dLow shl 16) or dP.toLong()
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

    // ── Bit helpers ───────────────────────────────────────────────────────────
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
            ConnectionPhase.IDLE          -> getString(R.string.vpn_status_connecting)
            ConnectionPhase.STARTING      -> getString(R.string.vpn_status_connecting)
            ConnectionPhase.FINDING_PROXY -> getString(R.string.vpn_status_starting_tunnel)
            ConnectionPhase.ACTIVE        -> "${getString(R.string.vpn_status_active)} · $proxyLabel"
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
