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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * RnetVpnService — Android VpnService that captures all device IP traffic
 * and routes it through the SOCKS5 proxy managed by RnetForegroundService.
 *
 * IMPORTANT: This service does NOT start Psiphon itself.
 * PsiphonTransport is owned by RnetForegroundService. When the SOCKS5 port
 * is ready, RnetForegroundService stores it in [RnetForegroundService.activeSocksPort]
 * and starts this service with that port as an Intent extra.
 *
 * How it works:
 *   1. Receive SOCKS5 port in ACTION_START intent extra (from RnetForegroundService).
 *   2. Establish a VPN tun interface capturing all IPv4 traffic.
 *   3. Forward TCP SYN packets through the SOCKS5 proxy.
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
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceScope: CoroutineScope? = null

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

                // Create a fresh scope each time (handles START_STICKY restarts)
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
            // Build VPN interface (blocking mode)
            val builder = Builder()
                .setSession("RNET")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 24)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute(VPN_ROUTE, VPN_PREFIX)
                .setBlocking(true)

            // Exclude our own app from the VPN to avoid routing loops
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            vpnInterface = builder.establish()
                ?: run {
                    Log.e(TAG, "VPN interface could not be established")
                    stopSelf()
                    return
                }

            updateNotification(getString(R.string.vpn_status_active))
            Log.i(TAG, "VPN interface established, forwarding via SOCKS5 :$socksPort")

            forwardTraffic(vpnInterface!!, socksPort)

        } catch (e: CancellationException) {
            Log.i(TAG, "VPN coroutine cancelled")
        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed: ${e.message}", e)
            updateNotification(getString(R.string.vpn_status_failed))
            stopSelf()
        }
    }

    private suspend fun forwardTraffic(tun: ParcelFileDescriptor, socksPort: Int) {
        val input = FileInputStream(tun.fileDescriptor)
        val packetBuf = ByteArray(VPN_MTU + 40)

        while (currentCoroutineContext().isActive) {
            try {
                val len = withContext(Dispatchers.IO) { input.read(packetBuf) }
                if (len <= 0) break

                val packet = packetBuf.copyOf(len)

                val ipVersion = (packet[0].toInt() and 0xFF) shr 4
                if (ipVersion != 4) continue

                val protocol = packet[9].toInt() and 0xFF
                if (protocol != 6) continue   // TCP only

                val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
                if (len < ipHeaderLen + 14) continue

                val destIpBytes = ByteArray(4)
                System.arraycopy(packet, 16, destIpBytes, 0, 4)
                val destIp = InetAddress.getByAddress(destIpBytes)

                val destPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                               (packet[ipHeaderLen + 3].toInt() and 0xFF)

                val tcpFlags = packet[ipHeaderLen + 13].toInt() and 0xFF
                if ((tcpFlags and 0x02) == 0) continue   // only SYN

                val scope = serviceScope ?: break
                scope.launch(Dispatchers.IO) {
                    try {
                        openSocks5Connection(destIp, destPort, socksPort)
                    } catch (e: Exception) {
                        Log.d(TAG, "SOCKS5 to $destIp:$destPort failed: ${e.message}")
                    }
                }

            } catch (e: CancellationException) {
                break
            } catch (e: Exception) {
                if (!currentCoroutineContext().isActive) break
                delay(10)
            }
        }
    }

    private fun openSocks5Connection(destIp: InetAddress, destPort: Int, socksPort: Int) {
        val sock = Socket()
        try {
            sock.connect(InetSocketAddress("127.0.0.1", socksPort), 5000)
            sock.soTimeout = 30000
            val sin  = sock.getInputStream()
            val sout = sock.getOutputStream()

            sout.write(byteArrayOf(0x05, 0x01, 0x00))
            sout.flush()
            val choice = ByteArray(2)
            if (sin.read(choice) < 2 || choice[1] != 0x00.toByte()) return

            val addr = destIp.address
            sout.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                addr[0], addr[1], addr[2], addr[3],
                (destPort shr 8).toByte(), (destPort and 0xFF).toByte()
            ))
            sout.flush()
            val response = ByteArray(10)
            if (sin.read(response) < 2 || response[1] != 0x00.toByte()) return

            Log.d(TAG, "SOCKS5 tunnel open: $destIp:$destPort")
            Thread.sleep(100)
        } finally {
            try { sock.close() } catch (_: Exception) {}
        }
    }

    private fun stopVpn() {
        serviceScope?.cancel()
        serviceScope = null
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
