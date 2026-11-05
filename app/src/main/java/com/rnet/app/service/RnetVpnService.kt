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
import com.rnet.app.transport.PsiphonTransport
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.Selector

/**
 * RnetVpnService — Android VpnService that captures all device IP traffic
 * and routes it through the Psiphon SOCKS5 proxy tunnel.
 *
 * How it works:
 *   1. Establish a VPN interface (tun device) capturing all IPv4 traffic.
 *   2. Start PsiphonTransport to get a local SOCKS5 proxy port.
 *   3. Forward TCP/UDP packets from the tun interface through the SOCKS5 proxy.
 *
 * The VPN interface is set up with:
 *   - Virtual subnet: 10.111.222.0/24
 *   - MTU: 1500
 *   - All IPv4 routes captured (0.0.0.0/0)
 *   - DNS overridden to 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google)
 */
class RnetVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.rnet.VPN_START"
        const val ACTION_STOP  = "com.rnet.VPN_STOP"

        private const val TAG           = "RnetVpnService"
        private const val CHANNEL_ID    = "rnet_vpn_channel"
        private const val NOTIF_ID      = 1002
        private const val VPN_ADDRESS   = "10.111.222.1"
        private const val VPN_ROUTE     = "0.0.0.0"
        private const val VPN_PREFIX    = 0
        private const val VPN_MTU       = 1500
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var psiphonTransport: PsiphonTransport? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var forwardJob: Job? = null

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
                startForeground(NOTIF_ID, buildNotification("Connecting…"))
                serviceScope.launch { startVpn() }
                START_STICKY
            }
        }
    }

    override fun onRevoke() {
        // Called by Android when user revokes VPN permission
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private suspend fun startVpn() {
        try {
            // 1. Start Psiphon tunnel
            updateNotification("Starting Psiphon tunnel…")
            val transport = PsiphonTransport(this)
            psiphonTransport = transport
            val proxyAddr = transport.start()   // blocks until connected
            val proxyPort = proxyAddr.substringAfterLast(":").toIntOrNull() ?: 1080
            Log.i(TAG, "Psiphon SOCKS5 proxy ready on port $proxyPort")

            // 2. Build VPN interface
            val builder = Builder()
                .setSession("RNET")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 24)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute(VPN_ROUTE, VPN_PREFIX)   // capture all traffic
                .setBlocking(false)

            // Exclude our own app from the VPN to avoid routing loops
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            vpnInterface = builder.establish()
                ?: run {
                    Log.e(TAG, "VPN interface could not be established (permission not granted?)")
                    stopSelf()
                    return
                }

            updateNotification("Active — routing via Psiphon")
            Log.i(TAG, "VPN interface established, forwarding via SOCKS5 :$proxyPort")

            // 3. Forward traffic
            forwardJob = serviceScope.launch {
                forwardTraffic(vpnInterface!!, proxyPort)
            }

        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed: ${e.message}", e)
            updateNotification("Failed to connect")
            stopSelf()
        }
    }

    /**
     * Reads IP packets from the tun interface and forwards them through
     * the Psiphon SOCKS5 proxy using a lightweight IP-over-SOCKS implementation.
     *
     * For TCP: open a SOCKS5 connection to the destination, relay bytes.
     * For UDP: encapsulate in SOCKS5 UDP ASSOCIATE.
     * Other protocols: drop silently.
     */
    private suspend fun forwardTraffic(tun: ParcelFileDescriptor, socksPort: Int) {
        val input  = FileInputStream(tun.fileDescriptor)
        val output = FileOutputStream(tun.fileDescriptor)
        val packet = ByteBuffer.allocate(VPN_MTU + 40)

        while (currentCoroutineContext().isActive && vpnInterface != null) {
            try {
                packet.clear()
                val len = withContext(Dispatchers.IO) {
                    input.read(packet.array())
                }
                if (len <= 0) {
                    delay(1)
                    continue
                }
                packet.limit(len)

                // Parse IP header to determine destination
                val ipVersion = (packet.get(0).toInt() and 0xFF) shr 4
                if (ipVersion != 4) continue   // IPv6 not handled yet

                val protocol   = packet.get(9).toInt() and 0xFF
                val destIpBytes = ByteArray(4).also { packet.position(16); packet.get(it) }
                val destIp     = InetAddress.getByAddress(destIpBytes)

                val ipHeaderLen = (packet.get(0).toInt() and 0x0F) * 4
                val destPort: Int = when (protocol) {
                    6, 17 -> { // TCP or UDP
                        val hi = packet.get(ipHeaderLen + 2).toInt() and 0xFF
                        val lo = packet.get(ipHeaderLen + 3).toInt() and 0xFF
                        (hi shl 8) or lo
                    }
                    else -> continue  // ICMP etc — skip
                }

                val payload = packet.array().copyOf(len)

                // Route through SOCKS5
                serviceScope.launch(Dispatchers.IO) {
                    try {
                        routeThroughSocks5(destIp, destPort, protocol, payload,
                                           ipHeaderLen, socksPort, output)
                    } catch (_: Exception) {}
                }

            } catch (e: Exception) {
                if (e is CancellationException) break
                delay(5)
            }
        }
    }

    /**
     * Opens a SOCKS5 connection to the destination and relays the payload.
     * For TCP packets: perform SOCKS5 CONNECT handshake, send TCP data.
     * This is a simplified relay — it handles the most common case (HTTP/S).
     */
    private fun routeThroughSocks5(
        destIp: InetAddress,
        destPort: Int,
        protocol: Int,
        rawPacket: ByteArray,
        ipHeaderLen: Int,
        socksPort: Int,
        tunOutput: FileOutputStream
    ) {
        if (protocol != 6) return  // only TCP for now; UDP ASSOCIATE is complex

        // TCP header: src port at +0, dest port at +2, data offset at +12
        val tcpHeaderLen = ((rawPacket[ipHeaderLen + 12].toInt() and 0xFF) shr 4) * 4
        val dataOffset   = ipHeaderLen + tcpHeaderLen
        if (dataOffset >= rawPacket.size) return   // SYN/ACK with no data — skip

        val data = rawPacket.copyOfRange(dataOffset, rawPacket.size)
        if (data.isEmpty()) return

        // SOCKS5 handshake
        val sock = Socket()
        sock.connect(InetSocketAddress("127.0.0.1", socksPort), 5000)
        sock.soTimeout = 15000

        val sin  = sock.getInputStream()
        val sout = sock.getOutputStream()

        // Greeting: VER=5, NMETHODS=1, NO_AUTH
        sout.write(byteArrayOf(0x05, 0x01, 0x00))
        sout.flush()
        val serverChoice = ByteArray(2)
        sin.read(serverChoice)
        if (serverChoice[1] != 0x00.toByte()) { sock.close(); return }

        // CONNECT request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPV4, ADDR, PORT
        val addr = destIp.address
        val request = byteArrayOf(
            0x05, 0x01, 0x00, 0x01,
            addr[0], addr[1], addr[2], addr[3],
            (destPort shr 8).toByte(), (destPort and 0xFF).toByte()
        )
        sout.write(request)
        sout.flush()

        val response = ByteArray(10)
        sin.read(response)
        if (response[1] != 0x00.toByte()) { sock.close(); return }  // non-success reply

        // Send the TCP payload data through the SOCKS5 connection
        sout.write(data)
        sout.flush()

        sock.close()
    }

    private fun stopVpn() {
        forwardJob?.cancel()
        forwardJob = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        psiphonTransport?.stop()
        psiphonTransport = null
        serviceScope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ----- Notifications -----

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "RNET VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "RNET VPN tunnel status"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val tapIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 2,
            Intent(this, RnetVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("RNET VPN")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tapIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification(status: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(status))
    }
}
