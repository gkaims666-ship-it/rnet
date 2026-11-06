package com.rnet.app.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.prefs.ServerPrefs
import com.rnet.app.service.ConnectionPhase
import com.rnet.app.service.DnsCache
import com.rnet.app.service.RnetForegroundService
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.CellSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class UiState(
    val engineActive: Boolean       = false,
    val gatewayActive: Boolean      = false,
    val snr: Float                  = 0f,
    val packetDeliveryRate: Float   = 1f,
    val activeStations: Int         = 0,
    val totalBytesIn: Long          = 0L,
    val totalBytesOut: Long         = 0L,
    val technology: String          = "--",
    val bandMhz: Int                = 0,
    val gatewayConsentGranted: Boolean = false,
    val useResilientCore: Boolean   = false,
    val errorMessage: String?       = null,
    // New fields
    val activeSessionCount: Int     = 0,        // live TCP sessions through the VPN
    val proxyLabel: String          = "—",      // "Smart·IS (12✓ 3⚡)" etc.
    val connectionPhase: ConnectionPhase = ConnectionPhase.IDLE,
    val exitRegion: String          = "",       // current exit country code e.g. "IS"
    val routeCacheSize: Int         = 0,        // cached routes (destinations with known fast exit)
    val pooledSockets: Int          = 0,        // pre-warmed sockets ready
    val dnsCacheSize: Int           = 0         // DNS entries in memory
)

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("rnet_prefs", Context.MODE_PRIVATE)

    private val _ui = MutableStateFlow(UiState(
        gatewayConsentGranted = prefs.getBoolean("gateway_consent_v1", false),
        useResilientCore = ServerPrefs.useResilientCore(app.applicationContext),
        exitRegion = prefs.getString("exit_region", "IS") ?: "IS"
    ))
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private val cellMonitor = CellMonitor(app.applicationContext)

    init {
        cellMonitor.start()
        viewModelScope.launch {
            cellMonitor.flow.collect { snap -> updateCellMetrics(snap) }
        }
        // Poll VPN byte counters every second while engine is active
        viewModelScope.launch {
            while (true) {
                delay(1_000)
                val bytesIn  = RnetForegroundService.activeBytesIn.get()
                val bytesOut = RnetForegroundService.activeBytesOut.get()
                val sessions = RnetForegroundService.activeSessionCount.get()
                val proxy    = RnetForegroundService.proxyLabel
                val phase    = RnetForegroundService.connectionPhase
                val region   = RnetForegroundService.exitRegion
                _ui.update { it.copy(
                    totalBytesIn       = bytesIn,
                    totalBytesOut      = bytesOut,
                    activeSessionCount = sessions,
                    proxyLabel         = proxy,
                    connectionPhase    = phase,
                    exitRegion         = region,
                    routeCacheSize     = RnetForegroundService.routeCacheSize,
                    pooledSockets      = RnetForegroundService.pooledSockets,
                    dnsCacheSize       = DnsCache.size()
                ) }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        cellMonitor.stop()
    }

    // ----- Engine toggle -----

    fun toggleEngine(active: Boolean) {
        val ctx = getApplication<Application>().applicationContext
        if (active) {
            val intent = Intent(ctx, RnetForegroundService::class.java).apply {
                action = RnetForegroundService.ACTION_START
            }
            ctx.startForegroundService(intent)
        } else {
            val intent = Intent(ctx, RnetForegroundService::class.java).apply {
                action = RnetForegroundService.ACTION_STOP
            }
            ctx.startService(intent)
        }
        _ui.update { it.copy(engineActive = active) }
    }

    fun toggleGateway(active: Boolean) {
        val ctx = getApplication<Application>().applicationContext
        val intent = Intent(ctx, RnetForegroundService::class.java).apply {
            action = if (active) RnetForegroundService.ACTION_GATEWAY_START
                     else        RnetForegroundService.ACTION_GATEWAY_STOP
        }
        ctx.startService(intent)
        _ui.update { it.copy(gatewayActive = active) }
    }

    fun onConsentGranted() {
        _ui.update { it.copy(gatewayConsentGranted = true) }
    }

    fun updateStationMetrics(stations: Map<String, HotspotGateway.StationMetrics>,
                              bytesIn: Long, bytesOut: Long) {
        val totalActive = stations.values.sumOf { it.activeConns }
        _ui.update { it.copy(
            activeStations = totalActive,
            totalBytesIn   = bytesIn,
            totalBytesOut  = bytesOut
        ) }
    }

    fun updatePacketDelivery(pdr: Float) {
        _ui.update { it.copy(packetDeliveryRate = pdr.coerceIn(0f, 1f)) }
    }

    private fun updateCellMetrics(snap: CellSnapshot) {
        // Map RSRP (-140 to -44 dBm) to SNR percentage (0–100)
        val snr = ((snap.rsrpDbm + 140f) / 96f).coerceIn(0f, 1f) * 100f
        _ui.update { it.copy(
            snr        = snr,
            technology = snap.technology,
            bandMhz    = snap.bandMhz
        ) }
    }

    /**
     * Toggles the "Route via Resilient Core" opt-in.
     *
     * When enabled, the transport engine routes traffic through the Psiphon
     * decentralized network (psiphon.ca). The user sees this toggle and its
     * disclosure text before enabling. Requires app restart to take effect
     * if the engine is already running.
     */
    fun setUseResilientCore(enabled: Boolean) {
        ServerPrefs.setUseResilientCore(getApplication(), enabled)
        _ui.update { it.copy(useResilientCore = enabled) }
    }

    /** Force-set engine active flag without sending a service command (used for UI rollback). */
    fun setEngineActive(active: Boolean) {
        _ui.update { it.copy(engineActive = active) }
    }

    /**
     * Set the preferred Psiphon exit region (e.g. "IS", "DE", "US").
     * If the engine is running, sends ACTION_CHANGE_REGION for a live hot-swap
     * (no VPN disconnect required). Otherwise persists for next start.
     */
    fun setExitRegion(region: String) {
        prefs.edit().putString("exit_region", region).apply()
        RnetForegroundService.pendingRegion = region
        _ui.update { it.copy(exitRegion = region) }

        val ctx = getApplication<Application>().applicationContext
        if (_ui.value.engineActive) {
            // Live hot-swap — service handles the region change without disconnecting
            val intent = Intent(ctx, RnetForegroundService::class.java).apply {
                action = RnetForegroundService.ACTION_CHANGE_REGION
                putExtra(RnetForegroundService.EXTRA_REGION, region)
            }
            ctx.startService(intent)
        }
    }
}
