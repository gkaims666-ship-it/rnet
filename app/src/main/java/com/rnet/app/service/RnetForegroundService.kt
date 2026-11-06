package com.rnet.app.service

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.rnet.app.R
import com.rnet.app.crypto.HybridKeyExchange
import com.rnet.app.crypto.SessionCipher
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.prefs.ServerPrefs
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.MultipathEngine
import com.rnet.app.transport.PsiphonTransport
import com.rnet.app.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * RnetForegroundService — FOREGROUND_SERVICE_DATA_SYNC service that owns the
 * transport engine and gateway lifecycle.
 *
 * Actions:
 *   ACTION_START          → start VPN + engine
 *   ACTION_STOP           → stop engine + VPN
 *   ACTION_GATEWAY_START  → start HotspotGateway
 *   ACTION_GATEWAY_STOP   → stop gateway
 *
 * VPN startup sequence:
 *   1. ACTION_START received → startEngine()
 *   2. VPN interface started IMMEDIATELY in direct mode (no SOCKS5 needed)
 *   3. If "Route via Resilient Core" is enabled AND Psiphon connects successfully,
 *      restart the VPN in SOCKS5 mode on Psiphon's port (best-effort upgrade)
 *   4. Engine traffic counters (bytes in/out) are exposed via activeBytesIn/Out
 */
class RnetForegroundService : Service() {

    companion object {
        const val ACTION_START          = "com.rnet.START"
        const val ACTION_STOP           = "com.rnet.STOP"
        const val ACTION_GATEWAY_START  = "com.rnet.GATEWAY_START"
        const val ACTION_GATEWAY_STOP   = "com.rnet.GATEWAY_STOP"

        private const val CHANNEL_ID    = "rnet_service_channel"
        private const val NOTIF_ID      = 1001

        /**
         * The SOCKS5 port Psiphon is currently listening on.
         * 0 = not running (direct mode).
         */
        @Volatile var activeSocksPort: Int = 0

        /** Bytes transferred through the VPN — updated by RnetVpnService. */
        @Volatile var activeBytesIn:  Long = 0L
        @Volatile var activeBytesOut: Long = 0L
    }

    private lateinit var cellMonitor: CellMonitor
    private lateinit var engine: MultipathEngine
    private var psiphon: PsiphonTransport? = null
    private var gateway: HotspotGateway? = null

    @Volatile private var engineStarted  = false
    @Volatile private var gatewayStarted = false

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        cellMonitor = CellMonitor(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification(engineStarted, gatewayStarted))

        when (intent?.action) {
            ACTION_START         -> startEngine()
            ACTION_STOP          -> stopEngine()
            ACTION_GATEWAY_START -> startGateway()
            ACTION_GATEWAY_STOP  -> stopGateway()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopGateway()
        stopEngine()
        super.onDestroy()
    }

    // ----- Engine lifecycle -----

    private fun startEngine() {
        if (engineStarted) return
        engineStarted = true
        updateNotification()

        val sessionKeyBytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val cipher = SessionCipher(sessionKeyBytes)
        engine = MultipathEngine(this, cipher, cellMonitor)

        // Step 1: Start VPN in direct mode IMMEDIATELY.
        // This works without any external service or credentials.
        // Traffic flows: app → tun fd → RnetVpnService → (protected socket) → internet
        startVpnInterface(socksPort = 0)

        // Step 2: If "Route via Resilient Core" is ON, also start Psiphon in background.
        // If Psiphon connects, restart VPN in SOCKS5 mode for the upgrade.
        // If Psiphon fails, the VPN keeps working in direct mode — no disruption.
        if (ServerPrefs.useResilientCore(this)) {
            serviceScope.launch {
                try {
                    val psiphonTransport = PsiphonTransport(this@RnetForegroundService)
                    psiphon = psiphonTransport
                    val proxyAddress = psiphonTransport.start()
                    val port = proxyAddress.substringAfterLast(":").toIntOrNull() ?: 1080
                    activeSocksPort = port

                    android.util.Log.i("RnetForegroundService",
                        "Psiphon connected on port $port — upgrading VPN to SOCKS5 mode")

                    // Stop the direct-mode VPN, restart with SOCKS5
                    stopVpnInterface()
                    startVpnInterface(socksPort = port)

                    // Also connect MultipathEngine via SOCKS5 for multi-path UDP
                    val relayHost = ServerPrefs.getHost(this@RnetForegroundService)
                    val relayPort = ServerPrefs.getPort(this@RnetForegroundService)
                    engine.setUpstreamSocksProxy("127.0.0.1", port)
                    if (relayHost.isNotBlank() && relayHost != "relay.example.com") {
                        engine.start(relayHost, relayPort)
                    }
                } catch (e: Exception) {
                    android.util.Log.w("RnetForegroundService",
                        "Psiphon unavailable (${e.message}) — staying in direct mode")
                    // VPN already running in direct mode; nothing to do
                }
            }
        } else {
            // Standard mode: use relay if configured; otherwise VPN handles routing directly
            val relayHost = ServerPrefs.getHost(this)
            val relayPort = ServerPrefs.getPort(this)
            if (relayHost.isNotBlank() &&
                relayHost != "relay.example.com" &&
                !relayHost.endsWith(".example.com")) {
                engine.start(relayHost, relayPort)
            }
        }
    }

    /**
     * Start RnetVpnService.
     *
     * socksPort == 0  → direct mode (VPN routes straight to internet via protected sockets)
     * socksPort > 0   → SOCKS5 mode (VPN routes through the given proxy port)
     *
     * Uses startService() (not startForegroundService()) because this may be called
     * from a background coroutine after the initial onStartCommand() window has passed.
     * VpnService sub-classes are promoted to foreground automatically by the system
     * when they call startForeground() inside their own onStartCommand().
     */
    private fun startVpnInterface(socksPort: Int) {
        try {
            val intent = Intent(this, RnetVpnService::class.java).apply {
                action = RnetVpnService.ACTION_START
                putExtra(RnetVpnService.EXTRA_SOCKS_PORT, socksPort)
            }
            startService(intent)
            android.util.Log.i("RnetForegroundService",
                "VPN started (${if (socksPort > 0) "SOCKS5 :$socksPort" else "direct"})")
        } catch (e: Exception) {
            android.util.Log.w("RnetForegroundService",
                "Could not start VPN interface: ${e.message}")
        }
    }

    private fun stopVpnInterface() {
        try {
            startService(Intent(this, RnetVpnService::class.java).apply {
                action = RnetVpnService.ACTION_STOP
            })
        } catch (_: Exception) {}
    }

    private fun stopEngine() {
        if (!engineStarted) return
        stopVpnInterface()
        activeSocksPort = 0
        activeBytesIn   = 0
        activeBytesOut  = 0
        if (::engine.isInitialized) {
            runCatching { engine.stop() }
        }
        psiphon?.stop()
        psiphon = null
        engineStarted = false
        updateNotification()
        if (!gatewayStarted) stopSelf()
    }

    // ----- Gateway lifecycle -----

    private fun startGateway() {
        if (gatewayStarted) return
        if (!engineStarted) startEngine()

        val gw = HotspotGateway(this, engine)
        gw.grantConsent()
        gw.start()
        gateway = gw
        gatewayStarted = true
        updateNotification()
    }

    private fun stopGateway() {
        gateway?.stop()
        gateway = null
        gatewayStarted = false
        if (engineStarted) updateNotification()
    }

    // ----- Notifications -----

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "RNET Transport",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "RNET multi-path transport service"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(engineOn: Boolean, gatewayOn: Boolean): Notification {
        val tapIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, RnetForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        val statusText = buildString {
            if (engineOn)  append("Engine active")
            if (gatewayOn) append(" · Gateway on")
            if (!engineOn && !gatewayOn) append("Idle")
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(tapIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel,
                       getString(R.string.notif_stop), stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(engineStarted, gatewayStarted))
    }
}
