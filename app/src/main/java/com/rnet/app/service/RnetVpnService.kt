package com.rnet.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.rnet.app.R
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * RnetVpnService — Android VpnService that captures all device IP traffic
 * and routes it through a SOCKS5 proxy OR directly to the internet.
 *
 * Operation modes (determined by EXTRA_SOCKS_PORT in start intent):
 *
 *   MODE 1: Direct routing (socksPort == 0, default)
 *     The VPN tun interface is established, and each TCP connection is forwarded
 *     directly to the destination using a protected Socket. This bypasses the
 *     VPN interface itself to reach the real network, which is the standard
 *     tun2socks pattern used by all VPN clients (WireGuard, OpenVPN, etc.).
 *
 *   MODE 2: SOCKS5 proxy routing (socksPort > 0)
 *     Same as above but traffic is tunnelled through a local SOCKS5 proxy
 *     (e.g. Psiphon) before reaching the destination. Only used when the user
 *     explicitly enables "Route via Resilient Core."
 *
 * Traffic flow:
 *   App → kernel → tun fd → RnetVpnService → (optionally SOCKS5) → internet
 *
 * The service calls protect() on every outbound Socket so the routing loop
 * is broken: protected sockets bypass the VPN and use the underlying network.
 */
class RnetVpnService : VpnService() {

    companion object {
        const val ACTION_START      = "com.rnet.VPN_START"
        const val ACTION_STOP       = "com.rnet.VPN_STOP"
        /** Pass a valid SOCKS5 port here to route through a proxy; omit or 0 for direct routing. */
        const val EXTRA_SOCKS_PORT  = "socks_port"

        private const val TAG           = "RnetVpnService"
        private const val CHANNEL_ID    = "rnet_vpn_channel"
        private const val NOTIF_ID      = 1002
        private const val VPN_ADDRESS   = "10.111.222.1"
        private const val VPN_ROUTE     = "0.0.0.0"
        private const val VPN_PREFIX    = 0
        private const val VPN_MTU       = 1500
        private const val CONNECT_TIMEOUT_MS = 15_000

        // TCP flag constants
        private const val TCP_FIN = 0x01
        private const val TCP_SYN = 0x02
        private const val TCP_RST = 0x04
        private const val TCP_ACK = 0x10
        private const val TCP_PSH = 0x08

        private const val MAX_TUNNELS   = 128
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceScope: CoroutineScope? = null
    private val activeTunnels = AtomicInteger(0)

    // Active TCP tunnels keyed by "srcIp:srcPort:dstIp:dstPort"
    private val connections = ConcurrentHashMap<String, TcpSession>()

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                START_NOT_STICKY
            }
            else -> {
                // socksPort == 0 means direct routing mode (default, always works)
                val socksPort = intent?.getIntExtra(EXTRA_SOCKS_PORT, 0) ?: 0

                serviceScope?.cancel()
                serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

                startForeground(NOTIF_ID, buildNotification(getString(R.string.vpn_status_connecting)))
                serviceScope!!.launch { startVpn(socksPort) }
                START_STICKY
            }
        }
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private suspend fun startVpn(socksPort: Int) {
        try {
            val builder = Builder()
                .setSession("RNET")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 24)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute(VPN_ROUTE, VPN_PREFIX)
                .setBlocking(true)

            // Exclude our own app so we don't loop
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            vpnInterface = builder.establish()
                ?: run {
                    Log.e(TAG, "VPN interface could not be established — VPN permission not granted")
                    stopSelf()
                    return
                }

            val mode = if (socksPort > 0) "SOCKS5 :$socksPort" else "direct"
            updateNotification(getString(R.string.vpn_status_active))
            Log.i(TAG, "VPN interface established, routing mode: $mode")

            readPacketLoop(vpnInterface!!, socksPort)

        } catch (e: CancellationException) {
            Log.i(TAG, "VPN coroutine cancelled")
        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed: ${e.message}", e)
            updateNotification(getString(R.string.vpn_status_failed))
            stopSelf()
        }
    }

    // ── Main packet read loop ─────────────────────────────────────────────────

    private suspend fun readPacketLoop(tun: ParcelFileDescriptor, socksPort: Int) {
        val tunIn  = FileInputStream(tun.fileDescriptor)
        val tunOut = FileOutputStream(tun.fileDescriptor)
        val buf    = ByteArray(VPN_MTU + 40)
        val scope  = serviceScope ?: return

        while (currentCoroutineContext().isActive) {
            try {
                val len = withContext(Dispatchers.IO) { tunIn.read(buf) }
                if (len < 20) {
                    if (len <= 0) break
                    continue
                }

                // IPv4 version check
                val ver = (buf[0].toInt() and 0xFF) shr 4
                if (ver != 4) continue

                val ipHdrLen = (buf[0].toInt() and 0x0F) * 4
                if (len < ipHdrLen + 20) continue   // need at least TCP header

                val proto = buf[9].toInt() and 0xFF
                if (proto != 6) continue   // TCP only

                val srcIp = InetAddress.getByAddress(buf.copyOfRange(12, 16))
                val dstIp = InetAddress.getByAddress(buf.copyOfRange(16, 20))

                val to = ipHdrLen
                val srcPort   = readUShort(buf, to)
                val dstPort   = readUShort(buf, to + 2)
                val seqNum    = readUInt  (buf, to + 4)
                val ackNum    = readUInt  (buf, to + 8)
                val tcpHdrLen = ((buf[to + 12].toInt() and 0xFF) shr 4) * 4
                val flags     = buf[to + 13].toInt() and 0xFF

                val dataStart = to + tcpHdrLen
                val dataLen   = len - dataStart

                val key = connKey(srcIp, srcPort, dstIp, dstPort)

                when {
                    flags and TCP_RST != 0 -> {
                        connections.remove(key)?.close()
                    }
                    flags and TCP_SYN != 0 && flags and TCP_ACK == 0 -> {
                        // New connection — open tunnel to destination
                        if (activeTunnels.get() >= MAX_TUNNELS) {
                            sendRst(tunOut, dstIp, dstPort, srcIp, srcPort, seqNum + 1, 0)
                            continue
                        }
                        // Close any stale session for this key
                        connections.remove(key)?.close()

                        val session = TcpSession(
                            srcIp = srcIp, srcPort = srcPort,
                            dstIp = dstIp, dstPort = dstPort,
                            clientSeq = seqNum,
                            tunOut = tunOut
                        )
                        connections[key] = session
                        activeTunnels.incrementAndGet()

                        scope.launch(Dispatchers.IO) {
                            try {
                                session.connect(socksPort, this@RnetVpnService)
                                session.relayInbound()   // blocks until connection closed
                            } catch (e: Exception) {
                                Log.d(TAG, "Session $key failed: ${e.message}")
                            } finally {
                                connections.remove(key)
                                activeTunnels.decrementAndGet()
                                session.close()
                            }
                        }
                    }
                    flags and TCP_FIN != 0 -> {
                        connections[key]?.sendFin()
                        connections.remove(key)?.close()
                    }
                    else -> {
                        // Data or pure ACK
                        if (dataLen > 0) {
                            connections[key]?.sendOutbound(buf, dataStart, dataLen, seqNum, ackNum)
                        }
                    }
                }

            } catch (e: CancellationException) { break }
            catch (e: Exception) {
                if (!currentCoroutineContext().isActive) break
                delay(5)
            }
        }

        connections.values.forEach { it.close() }
        connections.clear()
    }

    // ── TCP Session ───────────────────────────────────────────────────────────

    /**
     * One proxied TCP connection. Opens a protected socket to the destination
     * (directly or via SOCKS5), tracks TCP sequence numbers, and relays data
     * bidirectionally between the socket and the tun fd.
     */
    private inner class TcpSession(
        val srcIp: InetAddress,
        val srcPort: Int,
        val dstIp: InetAddress,
        val dstPort: Int,
        clientSeq: Long,
        private val tunOut: FileOutputStream
    ) {
        // Server→client direction (we act as "server" on the VPN side)
        private val serverIsn: Long    = (System.nanoTime() and 0xFFFFFFFFL)
        @Volatile private var serverSeq: Long = serverIsn + 1  // after SYN-ACK

        // Client→server direction
        @Volatile private var clientSeq: Long = clientSeq + 1  // SYN consumes 1 seq

        private var sock: Socket? = null
        @Volatile private var closed = false

        /**
         * Connect to destination.
         *
         * Direct mode (socksPort == 0): open a plain Socket to dstIp:dstPort,
         * call protect() so it bypasses the VPN tun, and do the TCP handshake.
         *
         * SOCKS5 mode (socksPort > 0): open a plain Socket to 127.0.0.1:socksPort,
         * call protect(), then do the SOCKS5 CONNECT handshake.
         *
         * Either way, complete the client's TCP handshake by sending SYN-ACK.
         */
        fun connect(socksPort: Int, vpn: VpnService) {
            val socket = Socket()
            sock = socket
            // CRITICAL: protect() bypasses the VPN tun so we don't loop
            vpn.protect(socket)

            if (socksPort > 0) {
                // Route via SOCKS5 proxy
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0

                val sin  = socket.getInputStream()
                val sout = socket.getOutputStream()

                // SOCKS5 greeting — request no-auth
                sout.write(byteArrayOf(0x05, 0x01, 0x00))
                sout.flush()
                val greet = ByteArray(2).also { readFully(sin, it) }
                check(greet[1] == 0x00.toByte()) { "SOCKS5 auth not accepted: ${greet[1]}" }

                // SOCKS5 CONNECT request (IPv4)
                val addr = dstIp.address
                sout.write(byteArrayOf(
                    0x05, 0x01, 0x00, 0x01,
                    addr[0], addr[1], addr[2], addr[3],
                    (dstPort shr 8).toByte(), (dstPort and 0xFF).toByte()
                ))
                sout.flush()

                val resp = ByteArray(10).also { readFully(sin, it) }
                check(resp[1] == 0x00.toByte()) {
                    "SOCKS5 CONNECT refused, reply: ${resp[1].toInt() and 0xFF}"
                }
                Log.d(TAG, "SOCKS5→$dstIp:$dstPort established (src $srcIp:$srcPort)")
            } else {
                // Direct mode — connect protected socket straight to destination
                socket.connect(InetSocketAddress(dstIp, dstPort), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0
                Log.d(TAG, "Direct→$dstIp:$dstPort established (src $srcIp:$srcPort)")
            }

            // Complete the TCP three-way handshake by sending SYN-ACK to client
            sendTcpPacket(
                flags      = TCP_SYN or TCP_ACK,
                seqNum     = serverIsn,
                ackNum     = clientSeq,
                payload    = null, payloadLen = 0
            )
        }

        /** Relay inbound data: socket → tun → app. Blocks until connection ends. */
        fun relayInbound() {
            val sin = sock?.getInputStream() ?: return
            val buf = ByteArray(8192)
            try {
                while (!closed) {
                    val n = sin.read(buf)
                    if (n <= 0) break
                    sendTcpPacket(
                        flags      = TCP_PSH or TCP_ACK,
                        seqNum     = serverSeq,
                        ackNum     = clientSeq,
                        payload    = buf,
                        payloadLen = n
                    )
                    serverSeq += n
                    // Track bytes received (internet → app)
                    RnetForegroundService.activeBytesIn += n
                }
                // Send FIN-ACK when server closes
                if (!closed) {
                    sendTcpPacket(
                        flags   = TCP_FIN or TCP_ACK,
                        seqNum  = serverSeq,
                        ackNum  = clientSeq,
                        payload = null, payloadLen = 0
                    )
                }
            } catch (_: Exception) {}
        }

        /** Forward outbound data from the app (tun) to the real socket. */
        fun sendOutbound(buf: ByteArray, offset: Int, len: Int, seqNum: Long, ackNum: Long) {
            if (closed) return
            clientSeq = seqNum + len
            try {
                sock?.getOutputStream()?.let {
                    it.write(buf, offset, len)
                    it.flush()
                }
                // Track bytes sent (app → internet)
                RnetForegroundService.activeBytesOut += len
                // ACK back to client
                sendTcpPacket(
                    flags   = TCP_ACK,
                    seqNum  = serverSeq,
                    ackNum  = clientSeq,
                    payload = null, payloadLen = 0
                )
            } catch (e: Exception) {
                Log.d(TAG, "sendOutbound error: ${e.message}")
                close()
            }
        }

        fun sendFin() {
            if (closed) return
            try { sock?.close() } catch (_: Exception) {}
        }

        fun close() {
            closed = true
            try { sock?.close() } catch (_: Exception) {}
        }

        /**
         * Craft an IPv4+TCP response packet and write to tun fd.
         * Packet direction: dstIp:dstPort → srcIp:srcPort (server responding to client).
         */
        private fun sendTcpPacket(
            flags: Int, seqNum: Long, ackNum: Long,
            payload: ByteArray?, payloadLen: Int
        ) {
            val ipHdrLen  = 20
            val tcpHdrLen = 20
            val totalLen  = ipHdrLen + tcpHdrLen + payloadLen
            val pkt = ByteArray(totalLen)

            // IPv4 header (src=dstIp, dst=srcIp)
            pkt[0] = 0x45.toByte()
            pkt[1] = 0x00
            writeUShort(pkt, 2, totalLen)
            pkt[4] = 0x00; pkt[5] = 0x01   // ID
            pkt[6] = 0x40; pkt[7] = 0x00   // DF flag
            pkt[8] = 64                     // TTL
            pkt[9] = 6                      // TCP
            dstIp.address.copyInto(pkt, 12) // src = dstIp
            srcIp.address.copyInto(pkt, 16) // dst = srcIp

            // TCP header (srcPort=dstPort, dstPort=srcPort)
            val t = ipHdrLen
            writeUShort(pkt, t,     dstPort)
            writeUShort(pkt, t + 2, srcPort)
            writeUInt  (pkt, t + 4, seqNum)
            writeUInt  (pkt, t + 8, ackNum)
            pkt[t + 12] = 0x50.toByte()        // data offset = 5*4 = 20 bytes
            pkt[t + 13] = flags.toByte()
            pkt[t + 14] = 0xFF.toByte()        // window size high byte
            pkt[t + 15] = 0xFF.toByte()        // window size low byte

            if (payload != null && payloadLen > 0) {
                payload.copyInto(pkt, ipHdrLen + tcpHdrLen, 0, payloadLen)
            }

            // IP checksum
            writeUShort(pkt, 10, checksum16(pkt, 0, ipHdrLen))

            // TCP checksum (with pseudo-header)
            writeUShort(pkt, t + 16,
                tcpChecksum(pkt, ipHdrLen, tcpHdrLen + payloadLen,
                    dstIp.address, srcIp.address))

            synchronized(tunOut) {
                try { tunOut.write(pkt) } catch (_: Exception) {}
            }
        }
    }

    // ── Send RST helper ───────────────────────────────────────────────────────

    private fun sendRst(
        tunOut: FileOutputStream,
        srcIp: InetAddress, srcPort: Int,
        dstIp: InetAddress, dstPort: Int,
        seqNum: Long, ackNum: Long
    ) {
        val pkt = ByteArray(40)
        pkt[0] = 0x45.toByte(); pkt[1] = 0x00
        writeUShort(pkt, 2, 40)
        pkt[8] = 64; pkt[9] = 6
        srcIp.address.copyInto(pkt, 12)
        dstIp.address.copyInto(pkt, 16)
        writeUShort(pkt, 20, srcPort)
        writeUShort(pkt, 22, dstPort)
        writeUInt  (pkt, 24, seqNum)
        writeUInt  (pkt, 28, ackNum)
        pkt[32] = 0x50.toByte()
        pkt[33] = (TCP_RST or TCP_ACK).toByte()
        pkt[34] = 0xFF.toByte()
        pkt[35] = 0xFF.toByte()
        writeUShort(pkt, 10, checksum16(pkt, 0, 20))
        writeUShort(pkt, 36, tcpChecksum(pkt, 20, 20, srcIp.address, dstIp.address))
        synchronized(tunOut) {
            try { tunOut.write(pkt) } catch (_: Exception) {}
        }
    }

    // ── Checksum helpers ──────────────────────────────────────────────────────

    private fun checksum16(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        while (i < off + len - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if ((len and 1) != 0) sum += (buf[off + len - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun tcpChecksum(pkt: ByteArray, tcpOff: Int, tcpLen: Int,
                             srcIp: ByteArray, dstIp: ByteArray): Int {
        val pseudo = ByteArray(12 + tcpLen)
        srcIp.copyInto(pseudo, 0)
        dstIp.copyInto(pseudo, 4)
        pseudo[8] = 0x00; pseudo[9] = 0x06
        writeUShort(pseudo, 10, tcpLen)
        pkt.copyInto(pseudo, 12, tcpOff, tcpOff + tcpLen)
        return checksum16(pseudo, 0, pseudo.size)
    }

    // ── Byte-order helpers ────────────────────────────────────────────────────

    private fun readUShort(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    private fun readUInt(buf: ByteArray, off: Int): Long =
        (readUShort(buf, off).toLong() shl 16) or readUShort(buf, off + 2).toLong()

    private fun writeUShort(buf: ByteArray, off: Int, v: Int) {
        buf[off]     = (v ushr 8  and 0xFF).toByte()
        buf[off + 1] = (v         and 0xFF).toByte()
    }

    private fun writeUInt(buf: ByteArray, off: Int, v: Long) {
        buf[off]     = (v ushr 24 and 0xFF).toByte()
        buf[off + 1] = (v ushr 16 and 0xFF).toByte()
        buf[off + 2] = (v ushr 8  and 0xFF).toByte()
        buf[off + 3] = (v         and 0xFF).toByte()
    }

    private fun connKey(srcIp: InetAddress, srcPort: Int,
                         dstIp: InetAddress, dstPort: Int) =
        "${srcIp.hostAddress}:$srcPort:${dstIp.hostAddress}:$dstPort"

    private fun readFully(sin: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = sin.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.EOFException("Stream ended prematurely at $off/${buf.size}")
            off += n
        }
    }

    // ── Service lifecycle helpers ─────────────────────────────────────────────

    private fun stopVpn() {
        serviceScope?.cancel()
        serviceScope = null
        connections.values.forEach { it.close() }
        connections.clear()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, getString(R.string.notif_vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notif_vpn_channel_desc)
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val tapIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 2,
            Intent(this, RnetVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tapIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel,
                       getString(R.string.notif_stop), stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(status))
    }
}
