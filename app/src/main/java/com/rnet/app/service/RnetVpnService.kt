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
 * and routes it through the SOCKS5 proxy managed by RnetForegroundService.
 *
 * IMPORTANT: This service does NOT start Psiphon itself.
 * PsiphonTransport is owned by RnetForegroundService. When the SOCKS5 port
 * is ready, RnetForegroundService stores it in [RnetForegroundService.activeSocksPort]
 * and starts this service with that port as an Intent extra.
 *
 * Traffic flow (tun2socks pattern):
 *   1. Receive SOCKS5 port in ACTION_START intent extra (from RnetForegroundService).
 *   2. Establish a VPN tun interface capturing all IPv4 traffic.
 *   3. Read IP packets from tun fd, parse TCP headers.
 *   4. For each new TCP SYN: open a SOCKS5 tunnel to (destIp:destPort) through
 *      the Psiphon proxy at 127.0.0.1:socksPort.
 *   5. Track per-connection TCP state (seq/ack numbers, window size).
 *   6. Forward TCP payload bidirectionally with correct seq/ack tracking.
 *   7. Write crafted response packets back to the tun fd.
 */
class RnetVpnService : VpnService() {

    companion object {
        const val ACTION_START      = "com.rnet.VPN_START"
        const val ACTION_STOP       = "com.rnet.VPN_STOP"
        const val EXTRA_SOCKS_PORT  = "socks_port"

        private const val TAG           = "RnetVpnService"
        private const val CHANNEL_ID    = "rnet_vpn_channel"
        private const val NOTIF_ID      = 1002
        private const val VPN_ADDRESS   = "10.111.222.1"
        private const val VPN_ROUTE     = "0.0.0.0"
        private const val VPN_PREFIX    = 0
        private const val VPN_MTU       = 1500

        // TCP flag constants
        private const val TCP_FIN = 0x01
        private const val TCP_SYN = 0x02
        private const val TCP_RST = 0x04
        private const val TCP_ACK = 0x10
        private const val TCP_PSH = 0x08

        private const val MAX_TUNNELS   = 64
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
                val socksPort = intent?.getIntExtra(EXTRA_SOCKS_PORT, 0) ?: 0
                if (socksPort <= 0) {
                    Log.e(TAG, "ACTION_START received without valid SOCKS port — stopping")
                    stopSelf()
                    return START_NOT_STICKY
                }

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

            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            vpnInterface = builder.establish()
                ?: run {
                    Log.e(TAG, "VPN interface could not be established")
                    stopSelf()
                    return
                }

            updateNotification(getString(R.string.vpn_status_active))
            Log.i(TAG, "VPN interface established, forwarding via SOCKS5 :$socksPort")

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
                val srcPort = readUShort(buf, to)
                val dstPort = readUShort(buf, to + 2)
                val seqNum  = readUInt(buf, to + 4)
                val ackNum  = readUInt(buf, to + 8)
                val tcpHdrLen = ((buf[to + 12].toInt() and 0xFF) shr 4) * 4
                val flags   = buf[to + 13].toInt() and 0xFF
                val window  = readUShort(buf, to + 14)

                val dataStart = to + tcpHdrLen
                val dataLen   = len - dataStart

                val key = connKey(srcIp, srcPort, dstIp, dstPort)

                when {
                    flags and TCP_RST != 0 -> {
                        connections.remove(key)?.close()
                    }
                    flags and TCP_SYN != 0 && flags and TCP_ACK == 0 -> {
                        // New connection — open a SOCKS5 tunnel
                        if (activeTunnels.get() >= MAX_TUNNELS) {
                            sendRst(tunOut, dstIp, dstPort, srcIp, srcPort, seqNum + 1, 0)
                            continue
                        }
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
                        // Data or ACK — route to existing session
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
     * One proxied TCP connection. Tracks sequence numbers both ways so the
     * crafted response packets are accepted by the kernel.
     */
    private inner class TcpSession(
        val srcIp: InetAddress,
        val srcPort: Int,
        val dstIp: InetAddress,
        val dstPort: Int,
        clientSeq: Long,              // ISN from the client's SYN
        private val tunOut: FileOutputStream
    ) {
        // Server→client direction (we are the "server" from the VPN's perspective)
        private val serverIsn: Long    = 0x12345678L   // our initial sequence number
        @Volatile private var serverSeq: Long = serverIsn + 1  // after SYN-ACK
        // Client→server direction
        @Volatile private var clientSeq: Long = clientSeq + 1  // after SYN consumed

        private var sock: Socket? = null
        @Volatile private var closed = false

        /**
         * Connect to the SOCKS5 proxy for this session and send SYN-ACK back to
         * the client so the kernel completes the three-way handshake.
         */
        fun connect(socksPort: Int, vpn: VpnService) {
            val socket = Socket()
            sock = socket
            vpn.protect(socket)

            socket.connect(InetSocketAddress("127.0.0.1", socksPort), 10_000)
            socket.soTimeout = 0

            val sin  = socket.getInputStream()
            val sout = socket.getOutputStream()

            // SOCKS5 no-auth greeting
            sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
            val greet = ByteArray(2).also { readFully(sin, it) }
            check(greet[1] == 0x00.toByte()) { "SOCKS5 auth not accepted" }

            // SOCKS5 CONNECT request
            val addr = dstIp.address
            sout.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                addr[0], addr[1], addr[2], addr[3],
                (dstPort shr 8).toByte(), (dstPort and 0xFF).toByte()
            )); sout.flush()

            val resp = ByteArray(10).also { readFully(sin, it) }
            check(resp[1] == 0x00.toByte()) { "SOCKS5 CONNECT refused: ${resp[1]}" }

            Log.d(TAG, "SOCKS5 open $dstIp:$dstPort (src $srcIp:$srcPort)")

            // Send SYN-ACK back to the client to complete the handshake
            sendTcpPacket(
                flags   = TCP_SYN or TCP_ACK,
                seqNum  = serverIsn,
                ackNum  = clientSeq,
                payload = null, payloadLen = 0
            )
            // After SYN-ACK, server seq advances by 1 (SYN consumes a sequence number)
            serverSeq = serverIsn + 1
        }

        /** Relay inbound data: SOCKS5 proxy → tun → app. Blocks until connection ends. */
        fun relayInbound() {
            val sin = sock?.getInputStream() ?: return
            val buf = ByteArray(4096)
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
            } catch (_: Exception) {
                // Connection closed normally
            }
        }

        /** Forward outbound data from the app (via tun) to the SOCKS5 socket. */
        fun sendOutbound(buf: ByteArray, offset: Int, len: Int, seqNum: Long, ackNum: Long) {
            if (closed) return
            clientSeq = seqNum + len   // advance expected client seq
            try {
                sock?.getOutputStream()?.let {
                    it.write(buf, offset, len)
                    it.flush()
                }
                // Send ACK back to client
                sendTcpPacket(
                    flags   = TCP_ACK,
                    seqNum  = serverSeq,
                    ackNum  = clientSeq,
                    payload = null, payloadLen = 0
                )
            } catch (e: Exception) {
                Log.d(TAG, "sendOutbound failed: ${e.message}")
                close()
            }
        }

        fun sendFin() {
            if (closed) return
            try {
                sock?.close()
            } catch (_: Exception) {}
        }

        fun close() {
            closed = true
            try { sock?.close() } catch (_: Exception) {}
        }

        /**
         * Craft an IPv4+TCP packet and write it to the tun fd.
         * src = dstIp:dstPort (the remote server's perspective — response direction)
         * dst = srcIp:srcPort (the local app)
         */
        private fun sendTcpPacket(
            flags: Int,
            seqNum: Long,
            ackNum: Long,
            payload: ByteArray?,
            payloadLen: Int
        ) {
            val ipHdrLen  = 20
            val tcpHdrLen = 20
            val totalLen  = ipHdrLen + tcpHdrLen + payloadLen
            val pkt = ByteArray(totalLen)

            // IPv4 header (src=dstIp, dst=srcIp — response direction)
            pkt[0] = 0x45.toByte()
            pkt[1] = 0x00
            writeUShort(pkt, 2, totalLen)
            pkt[4] = 0x00; pkt[5] = 0x01   // ID
            pkt[6] = 0x40; pkt[7] = 0x00   // DF flag
            pkt[8] = 64                     // TTL
            pkt[9] = 6                      // TCP
            dstIp.address.copyInto(pkt, 12) // src = dstIp (server responding)
            srcIp.address.copyInto(pkt, 16) // dst = srcIp (client)

            // TCP header (srcPort=dstPort, dstPort=srcPort — response direction)
            val t = ipHdrLen
            writeUShort(pkt, t,     dstPort)   // src port = server port
            writeUShort(pkt, t + 2, srcPort)   // dst port = client port
            writeUInt  (pkt, t + 4, seqNum)
            writeUInt  (pkt, t + 8, ackNum)
            pkt[t + 12] = 0x50.toByte()        // data offset = 5 (20 bytes)
            pkt[t + 13] = flags.toByte()
            pkt[t + 14] = 0xFF.toByte()        // window high
            pkt[t + 15] = 0xFF.toByte()        // window low

            // Copy payload
            if (payload != null && payloadLen > 0) {
                payload.copyInto(pkt, ipHdrLen + tcpHdrLen, 0, payloadLen)
            }

            // IP checksum
            val ipCsum = checksum16(pkt, 0, ipHdrLen)
            writeUShort(pkt, 10, ipCsum)

            // TCP checksum (pseudo-header)
            val tcpCsum = tcpChecksum(pkt, ipHdrLen, tcpHdrLen + payloadLen,
                                       dstIp.address, srcIp.address)
            writeUShort(pkt, t + 16, tcpCsum)

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
        writeUShort(pkt, 10, checksum16(pkt, 0, 20))
        val tcsum = tcpChecksum(pkt, 20, 20, srcIp.address, dstIp.address)
        writeUShort(pkt, 36, tcsum)
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
            if (n < 0) throw java.io.EOFException("Stream ended after $off/${buf.size} bytes")
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
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(status))
    }
}
