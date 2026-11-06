package com.rnet.app.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.prefs.ServerPrefs
import com.rnet.app.service.RnetForegroundService
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.CellSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class UiState(
    val engineActive: Boolean       = false,
    val gatewayActive: Boolean      = false,
    val snr: Float                  = 0f,       // Signal-to-noise ratio proxy (RSRP + offset)
    val packetDeliveryRate: Float   = 1f,       // 0.0–1.0
    val activeStations: Int         = 0,
    val totalBytesIn: Long          = 0L,
    val totalBytesOut: Long         = 0L,
    val technology: String          = "--",
    val bandMhz: Int                = 0,
    val gatewayConsentGranted: Boolean = false,
    val useResilientCore: Boolean   = false,    // user opt-in: route via Psiphon
    val errorMessage: String?       = null
)

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("rnet_prefs", Context.MODE_PRIVATE)

    private val _ui = MutableStateFlow(UiState(
        gatewayConsentGranted = prefs.getBoolean("gateway_consent_v1", false),
        useResilientCore = ServerPrefs.useResilientCore(app.applicationContext)
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
                val bytesIn  = RnetForegroundService.activeBytesIn
                val bytesOut = RnetForegroundService.activeBytesOut
                if (bytesIn != _ui.value.totalBytesIn || bytesOut != _ui.value.totalBytesOut) {
                    _ui.update { it.copy(totalBytesIn = bytesIn, totalBytesOut = bytesOut) }
                }
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
}
