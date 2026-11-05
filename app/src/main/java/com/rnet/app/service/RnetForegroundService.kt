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
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.MultipathEngine
import com.rnet.app.ui.MainActivity

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

        // TODO: replace with actual server host/port from configuration
        private const val REMOTE_HOST   = "your.rnet.server.example.com"
        private const val REMOTE_PORT   = 7777
    }

    private lateinit var cellMonitor: CellMonitor
    private lateinit var engine: MultipathEngine
    private var gateway: HotspotGateway? = null

    private var engineStarted  = false
    private var gatewayStarted = false

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

        // Perform key exchange — in production this connects to a signaling server
        val localX25519KP  = HybridKeyExchange.generateX25519KeyPair()
        val sessionKeyBytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        // ^^ In a full deployment, sessionKeyBytes comes from the hybrid handshake;
        //    this placeholder ensures the service compiles and starts cleanly.
        val cipher = SessionCipher(sessionKeyBytes)

        engine = MultipathEngine(this, cipher, cellMonitor)
        cellMonitor.start()
        engine.start(REMOTE_HOST, REMOTE_PORT)
        engineStarted = true
        updateNotification()
    }

    private fun stopEngine() {
        if (!engineStarted) return
        engine.stop()
        cellMonitor.stop()
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
