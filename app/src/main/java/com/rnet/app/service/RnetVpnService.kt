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
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * RnetVpnService — Android VpnService that captures all device IP traffic
 * and routes it through the internet using protected sockets.
 *
 * Operation modes (determined by EXTRA_SOCKS_PORT):
 *
 *   MODE 1: Direct routing (socksPort == 0, default)
 *     TCP connections are forwarded directly to the destination using a
 *     protected Socket. UDP DNS queries (port 53) are forwarded with a
 *     protected DatagramSocket. protect() breaks the routing loop so the
 *     socket uses the real network, not the VPN tun.
 *
 *   MODE 2: SOCKS5 proxy routing (socksPort > 0)
 *     TCP connections are tunnelled through the given SOCKS5 proxy port.
 *     DNS is still forwarded directly (SOCKS5 only handles TCP).
 *
 * Traffic flow:
 *   App → kernel → tun fd → RnetVpnService → (optionally SOCKS5) → internet
 *
 * DNS flow (UDP port 53):
 *   App DNS query → tun fd → RnetVpnService → protected DatagramSocket → 1.1.1.1:53
 *   Response ← crafted UDP response packet written back to tun fd
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
        private const val CONNECT_TIMEOUT_MS = 15_000

        // TCP flags
        private const val TCP_FIN = 0x01
        private const val TCP_SYN = 0x02
        private const val TCP_RST = 0x04
        private const val TCP_ACK = 0x10
        private const val TCP_PSH = 0x08

        private const val MAX_TUNNELS = 128

        // DNS resolver — use Cloudflare's as the upstream for queries from the VPN
        private val DNS_UPSTREAM = InetSocketAddress("1.1.1.1", 53)
        private const val DNS_TIMEOUT_MS = 5_000
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceScope: CoroutineScope? = null
    private val activeTunnels = AtomicInteger(0)
    private val connections = ConcurrentHashMap<String, TcpSession>()

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); START_NOT_STICKY }
            else -> {
                val socksPort = intent?.getIntExtra(EXTRA_SOCKS_PORT, 0) ?: 0
                serviceScope?.cancel()
                serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                startForeground(NOTIF_ID, buildNotification(getString(R.string.vpn_status_connecting)))
                serviceScope!!.launch { startVpn(socksPort) }
                START_STICKY
            }
        }
    }

    override fun onRevoke() { stopVpn(); super.onRevoke() }
    override fun onDestroy() { stopVpn(); super.onDestroy() }

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
                    Log.e(TAG, "VPN interface could not be established — VPN permission not granted")
                    stopSelf(); return
                }

            val mode = if (socksPort > 0) "SOCKS5 :$socksPort" else "direct"
            updateNotification(getString(R.string.vpn_status_active))
            Log.i(TAG, "VPN established — mode: $mode")

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
                if (len <= 0) break
                if (len < 20) continue

                // IPv4 only
                if ((buf[0].toInt() and 0xFF) shr 4 != 4) continue

                val ipHdrLen = (buf[0].toInt() and 0x0F) * 4
                val proto    = buf[9].toInt() and 0xFF

                val srcIp = InetAddress.getByAddress(buf.copyOfRange(12, 16))
                val dstIp = InetAddress.getByAddress(buf.copyOfRange(16, 20))

                when (proto) {
                    6 -> handleTcp(buf, len, ipHdrLen, srcIp, dstIp, tunOut, socksPort, scope)
                    17 -> handleUdp(buf, len, ipHdrLen, srcIp, dstIp, tunOut, scope)
                    // Other protocols: ignore (ICMP, etc.)
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

    // ── TCP handler ───────────────────────────────────────────────────────────

    private fun handleTcp(
        buf: ByteArray, len: Int, ipHdrLen: Int,
        srcIp: InetAddress, dstIp: InetAddress,
        tunOut: FileOutputStream, socksPort: Int,
        scope: CoroutineScope
    ) {
        if (len < ipHdrLen + 20) return

        val to = ipHdrLen
        val srcPort   = readU16(buf, to)
        val dstPort   = readU16(buf, to + 2)
        val seqNum    = readU32(buf, to + 4)
        val ackNum    = readU32(buf, to + 8)
        val tcpHdrLen = ((buf[to + 12].toInt() and 0xFF) shr 4) * 4
        val flags     = buf[to + 13].toInt() and 0xFF

        val dataStart = to + tcpHdrLen
        val dataLen   = (len - dataStart).coerceAtLeast(0)
        val key = connKey(srcIp, srcPort, dstIp, dstPort)

        when {
            flags and TCP_RST != 0 -> {
                connections.remove(key)?.close()
            }
            flags and TCP_SYN != 0 && flags and TCP_ACK == 0 -> {
                // New connection
                if (activeTunnels.get() >= MAX_TUNNELS) {
                    sendRst(tunOut, dstIp, dstPort, srcIp, srcPort, seqNum + 1, 0)
                    return
                }
                connections.remove(key)?.close()

                val session = TcpSession(srcIp, srcPort, dstIp, dstPort, seqNum, tunOut)
                connections[key] = session
                activeTunnels.incrementAndGet()

                scope.launch(Dispatchers.IO) {
                    try {
                        session.connect(socksPort, this@RnetVpnService)
                        session.relayInbound()
                    } catch (e: Exception) {
                        Log.d(TAG, "TCP $key: ${e.message}")
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
                if (dataLen > 0) {
                    connections[key]?.sendOutbound(buf, dataStart, dataLen, seqNum, ackNum)
                }
            }
        }
    }

    // ── UDP handler (DNS only) ────────────────────────────────────────────────

    private fun handleUdp(
        buf: ByteArray, len: Int, ipHdrLen: Int,
        srcIp: InetAddress, dstIp: InetAddress,
        tunOut: FileOutputStream, scope: CoroutineScope
    ) {
        if (len < ipHdrLen + 8) return

        val srcPort = readU16(buf, ipHdrLen)
        val dstPort = readU16(buf, ipHdrLen + 2)
        val udpLen  = readU16(buf, ipHdrLen + 4)   // includes 8-byte UDP header
        val dataLen = udpLen - 8

        if (dataLen <= 0) return

        // Only handle DNS queries (port 53) — forward everything else with direct UDP
        val payload = buf.copyOfRange(ipHdrLen + 8, ipHdrLen + 8 + dataLen)

        scope.launch(Dispatchers.IO) {
            forwardUdp(
                srcIp, srcPort, dstIp, dstPort,
                payload, tunOut
            )
        }
    }

    /**
     * Forward a UDP datagram using a protected DatagramSocket (bypasses VPN tun),
     * then write the response back as a crafted UDP/IPv4 packet into the tun fd.
     */
    private fun forwardUdp(
        srcIp: InetAddress, srcPort: Int,
        dstIp: InetAddress, dstPort: Int,
        payload: ByteArray,
        tunOut: FileOutputStream
    ) {
        try {
            val sock = DatagramSocket()
            protect(sock)   // bypass VPN tun so we reach real network
            sock.soTimeout = DNS_TIMEOUT_MS

            val sendPkt = DatagramPacket(payload, payload.size, dstIp, dstPort)
            sock.send(sendPkt)

            val respBuf = ByteArray(2048)
            val respPkt = DatagramPacket(respBuf, respBuf.size)
            sock.receive(respPkt)
            sock.close()

            val respLen = respPkt.length
            val resp    = respBuf.copyOf(respLen)

            // Build IPv4 + UDP response packet: src=dstIp:dstPort, dst=srcIp:srcPort
            val ipHdrLen  = 20
            val udpHdrLen = 8
            val total     = ipHdrLen + udpHdrLen + respLen
            val pkt = ByteArray(total)

            // IPv4 header
            pkt[0] = 0x45.toByte()
            pkt[1] = 0x00
            writeU16(pkt, 2, total)
            pkt[4] = 0x00; pkt[5] = 0x01
            pkt[6] = 0x40; pkt[7] = 0x00   // DF
            pkt[8] = 64                     // TTL
            pkt[9] = 17                     // UDP
            dstIp.address.copyInto(pkt, 12) // src
            srcIp.address.copyInto(pkt, 16) // dst
            writeU16(pkt, 10, checksum16(pkt, 0, ipHdrLen))

            // UDP header
            val t = ipHdrLen
            writeU16(pkt, t,     dstPort)
            writeU16(pkt, t + 2, srcPort)
            writeU16(pkt, t + 4, udpHdrLen + respLen)
            // UDP checksum — optional (0 = skip)
            pkt[t + 6] = 0; pkt[t + 7] = 0

            // Payload
            resp.copyInto(pkt, t + udpHdrLen)

            synchronized(tunOut) {
                try { tunOut.write(pkt) } catch (_: Exception) {}
            }

        } catch (e: Exception) {
            Log.d(TAG, "UDP forward $dstIp:$dstPort failed: ${e.message}")
        }
    }

    // ── TCP Session ───────────────────────────────────────────────────────────

    private inner class TcpSession(
        val srcIp: InetAddress, val srcPort: Int,
        val dstIp: InetAddress, val dstPort: Int,
        clientSeq: Long,
        private val tunOut: FileOutputStream
    ) {
        private val serverIsn: Long    = (System.nanoTime() and 0xFFFFFFFFL)
        @Volatile private var serverSeq: Long = serverIsn + 1
        @Volatile private var clientSeq: Long = clientSeq + 1

        private var sock: Socket? = null
        @Volatile private var closed = false

        fun connect(socksPort: Int, vpn: VpnService) {
            val socket = Socket()
            sock = socket
            vpn.protect(socket)   // CRITICAL: bypass VPN tun to reach real network

            if (socksPort > 0) {
                // Route via SOCKS5
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0
                val sin  = socket.getInputStream()
                val sout = socket.getOutputStream()

                sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
                val greet = ByteArray(2).also { readFully(sin, it) }
                check(greet[1] == 0x00.toByte()) { "SOCKS5 auth not accepted" }

                val addr = dstIp.address
                sout.write(byteArrayOf(
                    0x05, 0x01, 0x00, 0x01,
                    addr[0], addr[1], addr[2], addr[3],
                    (dstPort shr 8).toByte(), (dstPort and 0xFF).toByte()
                )); sout.flush()

                val resp = ByteArray(10).also { readFully(sin, it) }
                check(resp[1] == 0x00.toByte()) { "SOCKS5 CONNECT refused: ${resp[1].toInt() and 0xFF}" }
                Log.d(TAG, "SOCKS5→$dstIp:$dstPort ok")
            } else {
                // Direct connection — protected socket bypasses VPN tun
                socket.connect(InetSocketAddress(dstIp, dstPort), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0
                Log.d(TAG, "Direct→$dstIp:$dstPort ok")
            }

            // Send SYN-ACK to complete three-way handshake
            sendTcpPacket(TCP_SYN or TCP_ACK, serverIsn, clientSeq, null, 0)
        }

        fun relayInbound() {
            val sin = sock?.getInputStream() ?: return
            val buf = ByteArray(8192)
            try {
                while (!closed) {
                    val n = sin.read(buf)
                    if (n <= 0) break
                    sendTcpPacket(TCP_PSH or TCP_ACK, serverSeq, clientSeq, buf, n)
                    serverSeq += n
                    RnetForegroundService.activeBytesIn += n
                }
                if (!closed) sendTcpPacket(TCP_FIN or TCP_ACK, serverSeq, clientSeq, null, 0)
            } catch (_: Exception) {}
        }

        fun sendOutbound(buf: ByteArray, offset: Int, len: Int, seqNum: Long, ackNum: Long) {
            if (closed) return
            clientSeq = seqNum + len
            try {
                sock?.getOutputStream()?.let { it.write(buf, offset, len); it.flush() }
                RnetForegroundService.activeBytesOut += len
                sendTcpPacket(TCP_ACK, serverSeq, clientSeq, null, 0)
            } catch (e: Exception) {
                Log.d(TAG, "sendOutbound: ${e.message}")
                close()
            }
        }

        fun sendFin() { if (!closed) try { sock?.close() } catch (_: Exception) {} }
        fun close() { closed = true; try { sock?.close() } catch (_: Exception) {} }

        /**
         * Craft an IPv4+TCP response packet (src=dstIp:dstPort → dst=srcIp:srcPort)
         * and write it to the tun fd.
         */
        private fun sendTcpPacket(flags: Int, seqNum: Long, ackNum: Long,
                                   payload: ByteArray?, payloadLen: Int) {
            val ipLen = 20; val tcpLen = 20
            val total = ipLen + tcpLen + payloadLen
            val pkt   = ByteArray(total)

            // IPv4 header (src=dstIp, dst=srcIp — response direction)
            pkt[0] = 0x45.toByte(); pkt[1] = 0x00
            writeU16(pkt, 2, total)
            pkt[4] = 0x00; pkt[5] = 0x01   // ID
            pkt[6] = 0x40; pkt[7] = 0x00   // DF
            pkt[8] = 64; pkt[9] = 6        // TTL, TCP
            dstIp.address.copyInto(pkt, 12)
            srcIp.address.copyInto(pkt, 16)

            // TCP header (srcPort=dstPort, dstPort=srcPort)
            val t = ipLen
            writeU16(pkt, t,     dstPort)
            writeU16(pkt, t + 2, srcPort)
            writeU32(pkt, t + 4, seqNum)
            writeU32(pkt, t + 8, ackNum)
            pkt[t + 12] = 0x50.toByte()       // data offset = 5 (20 bytes)
            pkt[t + 13] = flags.toByte()
            pkt[t + 14] = 0xFF.toByte()        // window high
            pkt[t + 15] = 0xFF.toByte()        // window low

            if (payload != null && payloadLen > 0)
                payload.copyInto(pkt, ipLen + tcpLen, 0, payloadLen)

            writeU16(pkt, 10, checksum16(pkt, 0, ipLen))
            writeU16(pkt, t + 16,
                tcpChecksum(pkt, ipLen, tcpLen + payloadLen, dstIp.address, srcIp.address))

            synchronized(tunOut) { try { tunOut.write(pkt) } catch (_: Exception) {} }
        }
    }

    // ── Send RST ─────────────────────────────────────────────────────────────

    private fun sendRst(
        tunOut: FileOutputStream,
        srcIp: InetAddress, srcPort: Int,
        dstIp: InetAddress, dstPort: Int,
        seqNum: Long, ackNum: Long
    ) {
        val pkt = ByteArray(40)
        pkt[0] = 0x45.toByte(); pkt[1] = 0x00
        writeU16(pkt, 2, 40)
        pkt[8] = 64; pkt[9] = 6
        srcIp.address.copyInto(pkt, 12)
        dstIp.address.copyInto(pkt, 16)
        writeU16(pkt, 20, srcPort); writeU16(pkt, 22, dstPort)
        writeU32(pkt, 24, seqNum);  writeU32(pkt, 28, ackNum)
        pkt[32] = 0x50.toByte()
        pkt[33] = (TCP_RST or TCP_ACK).toByte()
        pkt[34] = 0xFF.toByte(); pkt[35] = 0xFF.toByte()
        writeU16(pkt, 10, checksum16(pkt, 0, 20))
        writeU16(pkt, 36, tcpChecksum(pkt, 20, 20, srcIp.address, dstIp.address))
        synchronized(tunOut) { try { tunOut.write(pkt) } catch (_: Exception) {} }
    }

    // ── Checksum helpers ──────────────────────────────────────────────────────

    private fun checksum16(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0; var i = off
        while (i < off + len - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (len and 1 != 0) sum += (buf[off + len - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun tcpChecksum(pkt: ByteArray, tcpOff: Int, tcpLen: Int,
                             srcIp: ByteArray, dstIp: ByteArray): Int {
        val pseudo = ByteArray(12 + tcpLen)
        srcIp.copyInto(pseudo, 0); dstIp.copyInto(pseudo, 4)
        pseudo[8] = 0x00; pseudo[9] = 0x06
        writeU16(pseudo, 10, tcpLen)
        pkt.copyInto(pseudo, 12, tcpOff, tcpOff + tcpLen)
        return checksum16(pseudo, 0, pseudo.size)
    }

    // ── Byte-order helpers ────────────────────────────────────────────────────

    private fun readU16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    /** Read big-endian unsigned 32-bit int as Long. */
    private fun readU32(buf: ByteArray, off: Int): Long {
        return ((buf[off].toLong()     and 0xFF) shl 24) or
               ((buf[off+1].toLong()   and 0xFF) shl 16) or
               ((buf[off+2].toLong()   and 0xFF) shl 8)  or
                (buf[off+3].toLong()   and 0xFF)
    }

    private fun writeU16(buf: ByteArray, off: Int, v: Int) {
        buf[off]     = (v ushr 8  and 0xFF).toByte()
        buf[off + 1] = (v         and 0xFF).toByte()
    }

    private fun writeU32(buf: ByteArray, off: Int, v: Long) {
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
            if (n < 0) throw java.io.EOFException("Premature EOF at $off/${buf.size}")
            off += n
        }
    }

    // ── Lifecycle helpers ─────────────────────────────────────────────────────

    private fun stopVpn() {
        serviceScope?.cancel(); serviceScope = null
        connections.values.forEach { it.close() }; connections.clear()
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
            ).apply { description = getString(R.string.notif_vpn_channel_desc); setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val tap  = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 2,
            Intent(this, RnetVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tap)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.notif_stop), stop)
            .setOngoing(true).setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(status))
    }
}
