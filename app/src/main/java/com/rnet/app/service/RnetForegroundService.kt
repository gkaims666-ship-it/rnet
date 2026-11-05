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
 * Runs as a persistent foreground service with a visible notification so the
 * user is always aware the transport stack is active. The OS will not kill it
 * during Doze without the user explicitly force-stopping the app.
 *
 * Actions:
 *   ACTION_START          → start MultipathEngine + CellMonitor
 *   ACTION_STOP           → stop engine
 *   ACTION_GATEWAY_START  → start HotspotGateway (consent already verified by UI)
 *   ACTION_GATEWAY_STOP   → stop gateway
 */
class RnetForegroundService : Service() {

    companion object {
        const val ACTION_START          = "com.rnet.START"
        const val ACTION_STOP           = "com.rnet.STOP"
        const val ACTION_GATEWAY_START  = "com.rnet.GATEWAY_START"
        const val ACTION_GATEWAY_STOP   = "com.rnet.GATEWAY_STOP"

        private const val CHANNEL_ID    = "rnet_service_channel"
        private const val NOTIF_ID      = 1001

        private const val DEFAULT_PORT  = 7777

        /**
         * The SOCKS5 port Psiphon is currently listening on.
         * Set when Psiphon connects, cleared when it stops.
         * Read by MainActivity to pass to RnetVpnService.
         */
        @Volatile var activeSocksPort: Int = 0
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

        // Session key: in production derived via HybridKeyExchange handshake
        val sessionKeyBytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val cipher = SessionCipher(sessionKeyBytes)

        engine = MultipathEngine(this, cipher, cellMonitor)
        // Note: cellMonitor.start() is intentionally NOT called here.
        // MainViewModel manages its own CellMonitor for UI telemetry.
        // MultipathEngine reads from cellMonitor.flow for MTU adaptation
        // but starting a second telephony listener would cause a crash.

        if (ServerPrefs.useResilientCore(this)) {
            // User has opted in to Psiphon resilient routing.
            // Start the Psiphon tunnel first; once connected, point the engine
            // at the SOCKS5 proxy it exposes locally.
            engineStarted = true          // mark started so the notification updates
            updateNotification()
            serviceScope.launch {
                try {
                    val psiphonTransport = PsiphonTransport(this@RnetForegroundService)
                    psiphon = psiphonTransport
                    // start() blocks until the first Psiphon server is reachable
                    val proxyAddress = psiphonTransport.start()
                    // proxyAddress = "socks5://127.0.0.1:<port>"
                    val port = proxyAddress.substringAfterLast(":").toIntOrNull() ?: 1080
                    activeSocksPort = port   // publish for RnetVpnService to read
                    engine.setUpstreamSocksProxy("127.0.0.1", port)
                    // Connect to user relay if configured; otherwise the SOCKS proxy
                    // itself is the exit (Psiphon handles the upstream path)
                    val relayHost = ServerPrefs.getHost(this@RnetForegroundService)
                    val relayPort = ServerPrefs.getPort(this@RnetForegroundService)
                    if (relayHost.isNotBlank()) {
                        engine.start(relayHost, relayPort)
                    } else {
                        // No private relay: Psiphon is the full transport stack
                        engine.startSocksPassthrough("127.0.0.1", port)
                    }
                    // Start the VPN interface now that SOCKS5 is ready
                    startVpnInterface(activeSocksPort)
                } catch (e: Exception) {
                    android.util.Log.e("RnetForegroundService",
                        "Psiphon start failed: ${e.message}")
                    // Fall back to direct connection if Psiphon fails
                    val relayHost = ServerPrefs.getHost(this@RnetForegroundService)
                    val relayPort = ServerPrefs.getPort(this@RnetForegroundService)
                    if (relayHost.isNotBlank()) engine.start(relayHost, relayPort)
                }
            }
        } else {
            // Standard mode: connect to user-configured relay.
            // If relay host is blank or still the default placeholder, bypass
            // private relay entirely and fall through to Psiphon as primary upstream.
            val relayHost = ServerPrefs.getHost(this)
            val relayPort = ServerPrefs.getPort(this)
            val isBlankOrPlaceholder = relayHost.isBlank() ||
                relayHost == "relay.example.com" ||
                relayHost.endsWith(".example.com")

            if (isBlankOrPlaceholder) {
                // No relay configured — start Psiphon immediately as primary upstream
                engineStarted = true
                updateNotification()
                serviceScope.launch {
                    try {
                        val psiphonTransport = PsiphonTransport(this@RnetForegroundService)
                        psiphon = psiphonTransport
                        val proxyAddress = psiphonTransport.start()
                        val port = proxyAddress.substringAfterLast(":").toIntOrNull() ?: 1080
                        activeSocksPort = port   // publish for RnetVpnService to read
                        engine.setUpstreamSocksProxy("127.0.0.1", port)
                        engine.startSocksPassthrough("127.0.0.1", port)
                        // Start the VPN interface now that SOCKS5 is ready
                        startVpnInterface(port)
                    } catch (e: Exception) {
                        android.util.Log.e("RnetForegroundService",
                            "Psiphon fallback start failed: ${e.message}")
                    }
                }
            } else {
                engine.start(relayHost, relayPort)
                engineStarted = true
                updateNotification()
            }
        }
    }

    /** Starts RnetVpnService with the given SOCKS5 port. Called after Psiphon is ready. */
    private fun startVpnInterface(socksPort: Int) {
        try {
            val intent = Intent(this, RnetVpnService::class.java).apply {
                action = RnetVpnService.ACTION_START
                putExtra(RnetVpnService.EXTRA_SOCKS_PORT, socksPort)
            }
            startForegroundService(intent)
        } catch (e: Exception) {
            android.util.Log.w("RnetForegroundService",
                "Could not start VPN interface: ${e.message}")
        }
    }

    private fun stopEngine() {
        if (!engineStarted) return
        // Stop VPN interface first
        try {
            startService(Intent(this, RnetVpnService::class.java).apply {
                action = RnetVpnService.ACTION_STOP
            })
        } catch (_: Exception) {}
        activeSocksPort = 0
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
        gw.grantConsent()   // consent verified by ConsentActivity before this action fires
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
            .setSmallIcon(android.R.drawable.ic_menu_share)   // replace with branded icon
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
