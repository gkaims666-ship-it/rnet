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
import com.rnet.app.crypto.HybridKeyExchange
import com.rnet.app.crypto.SessionCipher
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.prefs.ServerPrefs
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.MultipathEngine
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * RnetForegroundService — combined foreground service + VPN service.
 *
 * Extends VpnService so it can call establish() directly without needing to
 * start a second service (which fails from background on Android 8+).
 *
 * Actions:
 *   ACTION_START         → establish VPN + start engine
 *   ACTION_STOP          → stop VPN + engine
 *   ACTION_GATEWAY_START → start HotspotGateway
 *   ACTION_GATEWAY_STOP  → stop gateway
 *
 * VPN traffic flow:
 *   App → kernel → tun fd → this service → protected Socket → internet
 *   DNS: UDP port 53 → protected DatagramSocket → 1.1.1.1:53 → response back to tun fd
 */
class RnetForegroundService : VpnService() {

    companion object {
        const val ACTION_START          = "com.rnet.START"
        const val ACTION_STOP           = "com.rnet.STOP"
        const val ACTION_GATEWAY_START  = "com.rnet.GATEWAY_START"
        const val ACTION_GATEWAY_STOP   = "com.rnet.GATEWAY_STOP"

        private const val TAG           = "RnetForegroundService"
        private const val CHANNEL_ID    = "rnet_service_channel"
        private const val NOTIF_ID      = 1001

        // VPN config
        private const val VPN_ADDRESS   = "10.111.222.1"
        private const val VPN_MTU       = 1500
        private const val MAX_TUNNELS   = 128
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val DNS_TIMEOUT_MS     = 5_000

        // TCP flag constants
        private const val TCP_FIN = 0x01
        private const val TCP_SYN = 0x02
        private const val TCP_RST = 0x04
        private const val TCP_PSH = 0x08
        private const val TCP_ACK = 0x10

        /** Bytes transferred through VPN — polled by MainViewModel every second. */
        @JvmField val activeBytesIn  = AtomicLong(0L)
        @JvmField val activeBytesOut = AtomicLong(0L)

        @Volatile var activeSocksPort: Int = 0
    }

    private var cellMonitor: CellMonitor? = null
    private var engine: MultipathEngine? = null
    private var gateway: HotspotGateway? = null

    @Volatile private var engineStarted  = false
    @Volatile private var gatewayStarted = false

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // VPN state
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetLoopJob: Job? = null
    private val activeTunnels = AtomicInteger(0)
    private val connections   = ConcurrentHashMap<String, TcpSession>()

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        cellMonitor = CellMonitor(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification())
        when (intent?.action) {
            ACTION_START         -> startEngine()
            ACTION_STOP          -> { stopEngine(); stopGateway() }
            ACTION_GATEWAY_START -> startGateway()
            ACTION_GATEWAY_STOP  -> stopGateway()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked")
        stopEngine()
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopGateway()
        stopEngine()
        serviceScope.cancel()
        super.onDestroy()
    }

    // ── Engine lifecycle ───────────────────────────────────────────────────────

    private fun startEngine() {
        if (engineStarted) return
        engineStarted = true
        activeBytesIn.set(0L)
        activeBytesOut.set(0L)
        updateNotification()

        val cipher = SessionCipher(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })
        val cm     = cellMonitor!!
        engine     = MultipathEngine(this, cipher, cm)
        cm.start()

        // Establish VPN interface on the main/IO thread — must happen in a coroutine
        // so we don't block onStartCommand, but serviceScope is attached to this service
        // so it won't be killed under us.
        packetLoopJob = serviceScope.launch { runVpn(socksPort = 0) }

        Log.i(TAG, "Engine started (direct mode)")
    }

    private fun stopEngine() {
        if (!engineStarted) return
        engineStarted = false
        packetLoopJob?.cancel()
        packetLoopJob = null
        tearDownVpn()
        engine?.let { runCatching { it.stop() } }
        engine = null
        cellMonitor?.stop()
        activeSocksPort = 0
        activeBytesIn.set(0L)
        activeBytesOut.set(0L)
        updateNotification()
        if (!gatewayStarted) stopSelf()
    }

    // ── VPN interface ─────────────────────────────────────────────────────────

    private suspend fun runVpn(socksPort: Int) {
        try {
            val builder = Builder()
                .setSession("RNET")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 24)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .setBlocking(true)

            // Exclude our own app from VPN to avoid loopback
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "establish() returned null — VPN permission not granted?")
                engineStarted = false
                updateNotification()
                return
            }
            vpnInterface = pfd
            Log.i(TAG, "VPN interface established ✓ (mode=${if (socksPort > 0) "SOCKS5:$socksPort" else "direct"})")
            updateNotification()

            // Run the packet forwarding loop — this blocks until the job is cancelled
            readPacketLoop(pfd, socksPort)

        } catch (e: CancellationException) {
            Log.i(TAG, "VPN coroutine cancelled")
        } catch (e: Exception) {
            Log.e(TAG, "VPN error: ${e.message}", e)
        } finally {
            tearDownVpn()
        }
    }

    private fun tearDownVpn() {
        connections.values.forEach { runCatching { it.close() } }
        connections.clear()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
    }

    // ── Packet loop ────────────────────────────────────────────────────────────

    private suspend fun readPacketLoop(tun: ParcelFileDescriptor, socksPort: Int) {
        val tunIn  = FileInputStream(tun.fileDescriptor)
        val tunOut = FileOutputStream(tun.fileDescriptor)
        val buf    = ByteArray(VPN_MTU + 40)
        val scope  = serviceScope

        while (currentCoroutineContext().isActive) {
            try {
                val len = withContext(Dispatchers.IO) { tunIn.read(buf) }
                if (len <= 0) break
                if (len < 20) continue

                // IPv4 header check
                val version = (buf[0].toInt() and 0xFF) shr 4
                if (version != 4) continue

                val ipHdrLen = (buf[0].toInt() and 0x0F) * 4
                if (len < ipHdrLen + 8) continue

                val proto  = buf[9].toInt() and 0xFF
                val srcIp  = InetAddress.getByAddress(buf.copyOfRange(12, 16))
                val dstIp  = InetAddress.getByAddress(buf.copyOfRange(16, 20))

                when (proto) {
                    6  -> handleTcp(buf, len, ipHdrLen, srcIp, dstIp, tunOut, socksPort, scope)
                    17 -> handleUdp(buf, len, ipHdrLen, srcIp, dstIp, tunOut, scope)
                }

            } catch (e: CancellationException) { break }
            catch (e: Exception) {
                if (!currentCoroutineContext().isActive) break
                // Brief pause on error to avoid tight spin
                delay(2)
            }
        }
    }

    // ── TCP handling ───────────────────────────────────────────────────────────

    private fun handleTcp(
        buf: ByteArray, len: Int, ipHdrLen: Int,
        srcIp: InetAddress, dstIp: InetAddress,
        tunOut: FileOutputStream, socksPort: Int,
        scope: CoroutineScope
    ) {
        if (len < ipHdrLen + 20) return
        val t         = ipHdrLen
        val srcPort   = u16(buf, t)
        val dstPort   = u16(buf, t + 2)
        val seqNum    = u32(buf, t + 4)
        val ackNum    = u32(buf, t + 8)
        val tcpHdrLen = ((buf[t + 12].toInt() and 0xFF) shr 4) * 4
        val flags     = buf[t + 13].toInt() and 0xFF
        val dataStart = t + tcpHdrLen
        val dataLen   = (len - dataStart).coerceAtLeast(0)
        val key       = connKey(srcIp, srcPort, dstIp, dstPort)

        when {
            flags and TCP_RST != 0 -> {
                connections.remove(key)?.close()
            }
            flags and TCP_SYN != 0 && flags and TCP_ACK == 0 -> {
                if (activeTunnels.get() >= MAX_TUNNELS) {
                    sendRst(tunOut, dstIp, dstPort, srcIp, srcPort, seqNum + 1, 0L)
                    return
                }
                connections.remove(key)?.close()
                val session = TcpSession(srcIp, srcPort, dstIp, dstPort, seqNum, tunOut)
                connections[key] = session
                activeTunnels.incrementAndGet()
                scope.launch(Dispatchers.IO) {
                    try {
                        session.connect(socksPort, this@RnetForegroundService)
                        session.relayInbound()
                    } catch (e: Exception) {
                        Log.d(TAG, "TCP[$key] ${e.javaClass.simpleName}: ${e.message}")
                    } finally {
                        connections.remove(key)
                        activeTunnels.decrementAndGet()
                        session.close()
                    }
                }
            }
            flags and TCP_FIN != 0 -> {
                connections.remove(key)?.also { it.sendFin(); it.close() }
            }
            else -> {
                if (dataLen > 0) {
                    connections[key]?.sendOutbound(buf, dataStart, dataLen, seqNum)
                } else if (flags and TCP_ACK != 0) {
                    // Pure ACK — update ack tracking but no data to forward
                    connections[key]?.updateAck(ackNum)
                }
            }
        }
    }

    // ── UDP handling ───────────────────────────────────────────────────────────

    private fun handleUdp(
        buf: ByteArray, len: Int, ipHdrLen: Int,
        srcIp: InetAddress, dstIp: InetAddress,
        tunOut: FileOutputStream, scope: CoroutineScope
    ) {
        val srcPort = u16(buf, ipHdrLen)
        val dstPort = u16(buf, ipHdrLen + 2)
        val udpLen  = u16(buf, ipHdrLen + 4)
        val dataLen = (udpLen - 8).coerceAtLeast(0)
        if (dataLen == 0) return

        val payload = buf.copyOfRange(ipHdrLen + 8, ipHdrLen + 8 + dataLen.coerceAtMost(len - ipHdrLen - 8))

        scope.launch(Dispatchers.IO) {
            try {
                val sock = DatagramSocket()
                protect(sock)
                sock.soTimeout = DNS_TIMEOUT_MS

                sock.send(DatagramPacket(payload, payload.size, dstIp, dstPort))

                val respBuf = ByteArray(2048)
                val respPkt = DatagramPacket(respBuf, respBuf.size)
                sock.receive(respPkt)
                sock.close()

                val resp    = respBuf.copyOf(respPkt.length)
                val respLen = resp.size
                val total   = 20 + 8 + respLen
                val pkt     = ByteArray(total)

                // IPv4 header (src=dstIp, dst=srcIp — response direction)
                pkt[0] = 0x45.toByte()
                w16(pkt, 2, total)
                pkt[4] = 0; pkt[5] = 1
                pkt[6] = 0x40.toByte(); pkt[7] = 0  // DF
                pkt[8] = 64; pkt[9] = 17             // TTL=64, UDP
                dstIp.address.copyInto(pkt, 12)
                srcIp.address.copyInto(pkt, 16)
                w16(pkt, 10, ipChecksum(pkt, 0, 20))

                // UDP header
                w16(pkt, 20, dstPort)
                w16(pkt, 22, srcPort)
                w16(pkt, 24, 8 + respLen)
                pkt[26] = 0; pkt[27] = 0  // checksum optional for UDP

                resp.copyInto(pkt, 28)

                synchronized(tunOut) {
                    try { tunOut.write(pkt) } catch (_: Exception) {}
                }

            } catch (e: Exception) {
                Log.d(TAG, "UDP forward $dstIp:$dstPort failed: ${e.message}")
            }
        }
    }

    // ── TcpSession ─────────────────────────────────────────────────────────────

    private inner class TcpSession(
        val srcIp: InetAddress, val srcPort: Int,
        val dstIp: InetAddress, val dstPort: Int,
        clientSeq: Long,
        private val tunOut: FileOutputStream
    ) {
        // Server side of the connection — we generate our own ISN
        private val serverIsn: Long       = (System.nanoTime() and 0xFFFFFFFFL)
        @Volatile private var serverSeq   = serverIsn + 1  // after SYN-ACK is sent
        @Volatile private var clientSeq   = clientSeq + 1  // after receiving SYN

        private var sock: Socket? = null
        @Volatile private var closed = false

        /**
         * Open a protected socket to the destination.
         * protect() makes the socket bypass the VPN tun fd, reaching real internet.
         */
        fun connect(socksPort: Int, vpn: VpnService) {
            val socket = Socket()
            sock = socket
            vpn.protect(socket)  // MUST be called before connect() to break routing loop

            if (socksPort > 0) {
                // Route via SOCKS5 proxy (Psiphon)
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0
                val sin  = socket.getInputStream()
                val sout = socket.getOutputStream()
                // SOCKS5 greeting
                sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
                val greet = ByteArray(2).also { readFully(sin, it) }
                require(greet[1] == 0x00.toByte()) { "SOCKS5 auth not supported: ${greet[1].toInt() and 0xFF}" }
                // CONNECT to destination
                val addr = dstIp.address
                sout.write(byteArrayOf(
                    0x05, 0x01, 0x00, 0x01,
                    addr[0], addr[1], addr[2], addr[3],
                    (dstPort shr 8).toByte(), (dstPort and 0xFF).toByte()
                )); sout.flush()
                val resp = ByteArray(10).also { readFully(sin, it) }
                require(resp[1] == 0x00.toByte()) { "SOCKS5 CONNECT refused: ${resp[1].toInt() and 0xFF}" }
                Log.d(TAG, "SOCKS5 → $dstIp:$dstPort ok")
            } else {
                // Direct connection — protected socket goes via real network
                socket.connect(InetSocketAddress(dstIp, dstPort), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0
                Log.d(TAG, "Direct → $dstIp:$dstPort ok")
            }

            // Complete the three-way handshake by sending SYN-ACK back to the app
            sendTcpPacket(TCP_SYN or TCP_ACK, serverIsn, clientSeq, null, 0)
        }

        /** Relay inbound data from the real connection back to the app via tun fd. */
        fun relayInbound() {
            val sin = sock?.getInputStream() ?: return
            val buf = ByteArray(8192)
            try {
                while (!closed) {
                    val n = sin.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    sendTcpPacket(TCP_PSH or TCP_ACK, serverSeq, clientSeq, buf, n)
                    serverSeq += n
                    activeBytesIn.addAndGet(n.toLong())
                }
                // Connection closed cleanly — send FIN
                if (!closed) sendTcpPacket(TCP_FIN or TCP_ACK, serverSeq, clientSeq, null, 0)
            } catch (_: Exception) {}
        }

        /** Forward outbound data from app (via tun) to the real connection. */
        fun sendOutbound(buf: ByteArray, offset: Int, len: Int, seqNum: Long) {
            if (closed) return
            clientSeq = seqNum + len
            try {
                val sout = sock?.getOutputStream() ?: return
                sout.write(buf, offset, len)
                sout.flush()
                activeBytesOut.addAndGet(len.toLong())
                // ACK the data we just forwarded
                sendTcpPacket(TCP_ACK, serverSeq, clientSeq, null, 0)
            } catch (e: Exception) {
                Log.d(TAG, "sendOutbound $dstIp:$dstPort: ${e.message}")
                close()
            }
        }

        fun updateAck(@Suppress("UNUSED_PARAMETER") ackNum: Long) {
            // Slide server window — no-op in our simple implementation
        }

        fun sendFin() {
            if (!closed) {
                try { sock?.shutdownOutput() } catch (_: Exception) {}
            }
        }

        fun close() {
            closed = true
            try { sock?.close() } catch (_: Exception) {}
        }

        /**
         * Craft an IPv4 + TCP packet and write it to the tun fd.
         * Direction: src=dstIp:dstPort → dst=srcIp:srcPort (response from server to app).
         */
        private fun sendTcpPacket(
            flags: Int, seqNum: Long, ackNum: Long,
            payload: ByteArray?, payloadLen: Int
        ) {
            val pLen  = if (payload != null && payloadLen > 0) payloadLen else 0
            val total = 20 + 20 + pLen
            val pkt   = ByteArray(total)

            // IPv4 header
            pkt[0] = 0x45.toByte()          // version=4, IHL=5
            pkt[1] = 0x10                    // DSCP=4 (low-latency)
            w16(pkt, 2, total)
            pkt[4] = 0; pkt[5] = 0           // ID
            pkt[6] = 0x40.toByte(); pkt[7] = 0  // DF flag
            pkt[8] = 64                      // TTL
            pkt[9] = 6                       // protocol = TCP
            // checksum at offset 10 — filled below
            dstIp.address.copyInto(pkt, 12)  // src = server's real IP
            srcIp.address.copyInto(pkt, 16)  // dst = app's virtual IP

            // TCP header
            val t = 20
            w16(pkt, t,     dstPort)         // src port = server's port
            w16(pkt, t + 2, srcPort)         // dst port = app's port
            w32(pkt, t + 4, seqNum)
            w32(pkt, t + 8, ackNum)
            pkt[t + 12] = 0x50.toByte()      // data offset = 5 (20 bytes), no options
            pkt[t + 13] = flags.toByte()
            pkt[t + 14] = 0xFF.toByte()      // window size high byte
            pkt[t + 15] = 0xFF.toByte()      // window size low byte
            // checksum at t+16 — filled below
            pkt[t + 18] = 0; pkt[t + 19] = 0  // urgent pointer

            // Copy payload
            if (pLen > 0) payload!!.copyInto(pkt, 40, 0, pLen)

            // Fill checksums
            w16(pkt, 10, ipChecksum(pkt, 0, 20))
            w16(pkt, t + 16, tcpChecksum(pkt, 20, 20 + pLen, dstIp.address, srcIp.address))

            synchronized(tunOut) {
                try { tunOut.write(pkt) } catch (_: Exception) {}
            }
        }
    }

    // ── RST helper ─────────────────────────────────────────────────────────────

    private fun sendRst(
        tunOut: FileOutputStream,
        srcIp: InetAddress, srcPort: Int,
        dstIp: InetAddress, dstPort: Int,
        seqNum: Long, ackNum: Long
    ) {
        val pkt = ByteArray(40)
        pkt[0] = 0x45.toByte(); w16(pkt, 2, 40)
        pkt[8] = 64; pkt[9] = 6
        srcIp.address.copyInto(pkt, 12); dstIp.address.copyInto(pkt, 16)
        w16(pkt, 20, srcPort); w16(pkt, 22, dstPort)
        w32(pkt, 24, seqNum);  w32(pkt, 28, ackNum)
        pkt[32] = 0x50.toByte()
        pkt[33] = (TCP_RST or TCP_ACK).toByte()
        pkt[34] = 0xFF.toByte(); pkt[35] = 0xFF.toByte()
        w16(pkt, 10, ipChecksum(pkt, 0, 20))
        w16(pkt, 36, tcpChecksum(pkt, 20, 20, srcIp.address, dstIp.address))
        synchronized(tunOut) { try { tunOut.write(pkt) } catch (_: Exception) {} }
    }

    // ── Checksum helpers ───────────────────────────────────────────────────────

    private fun ipChecksum(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i   = off
        while (i < off + len - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i   += 2
        }
        if (len and 1 != 0) sum += (buf[off + len - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun tcpChecksum(pkt: ByteArray, tcpOff: Int, tcpLen: Int,
                             srcIp: ByteArray, dstIp: ByteArray): Int {
        val pseudo = ByteArray(12 + tcpLen)
        srcIp.copyInto(pseudo, 0)
        dstIp.copyInto(pseudo, 4)
        pseudo[8] = 0; pseudo[9] = 6
        w16(pseudo, 10, tcpLen)
        pkt.copyInto(pseudo, 12, tcpOff, tcpOff + tcpLen)
        return ipChecksum(pseudo, 0, pseudo.size)
    }

    // ── Byte-order helpers ─────────────────────────────────────────────────────

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    private fun u32(buf: ByteArray, off: Int): Long =
        ((buf[off    ].toLong() and 0xFF) shl 24) or
        ((buf[off + 1].toLong() and 0xFF) shl 16) or
        ((buf[off + 2].toLong() and 0xFF) shl  8) or
         (buf[off + 3].toLong() and 0xFF)

    private fun w16(buf: ByteArray, off: Int, v: Int) {
        buf[off]     = (v ushr 8  and 0xFF).toByte()
        buf[off + 1] = (v         and 0xFF).toByte()
    }

    private fun w32(buf: ByteArray, off: Int, v: Long) {
        buf[off]     = (v ushr 24 and 0xFF).toByte()
        buf[off + 1] = (v ushr 16 and 0xFF).toByte()
        buf[off + 2] = (v ushr  8 and 0xFF).toByte()
        buf[off + 3] = (v         and 0xFF).toByte()
    }

    private fun connKey(srcIp: InetAddress, srcPort: Int, dstIp: InetAddress, dstPort: Int) =
        "${srcIp.hostAddress}:$srcPort→${dstIp.hostAddress}:$dstPort"

    private fun readFully(sin: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = sin.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.EOFException("EOF at $off/${buf.size}")
            off += n
        }
    }

    // ── Gateway lifecycle ──────────────────────────────────────────────────────

    private fun startGateway() {
        if (gatewayStarted) return
        if (!engineStarted) startEngine()
        val gw = HotspotGateway(this, engine!!)
        gw.grantConsent(); gw.start()
        gateway = gw; gatewayStarted = true
        updateNotification()
    }

    private fun stopGateway() {
        gateway?.stop()
        gateway = null
        gatewayStarted = false
        if (engineStarted) updateNotification()
    }

    // ── Notifications ──────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "RNET Transport", NotificationManager.IMPORTANCE_LOW)
                .apply { description = "RNET VPN tunnel"; setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification {
        val tap  = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1,
            Intent(this, RnetForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE)
        val text = when {
            engineStarted && gatewayStarted -> "Engine active · Gateway on"
            engineStarted                   -> "VPN active"
            else                            -> "Idle"
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tap)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.notif_stop), stop)
            .setOngoing(true)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification() {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification())
    }
}
