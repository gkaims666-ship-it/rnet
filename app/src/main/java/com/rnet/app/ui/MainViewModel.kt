package com.rnet.app.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.rnet.app.gateway.HotspotGateway
import com.rnet.app.service.RnetForegroundService
import com.rnet.app.transport.CellMonitor
import com.rnet.app.transport.CellSnapshot
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
    val errorMessage: String?       = null
)

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("rnet_prefs", Context.MODE_PRIVATE)

    private val _ui = MutableStateFlow(UiState(
        gatewayConsentGranted = prefs.getBoolean("gateway_consent_v1", false)
    ))
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private val cellMonitor = CellMonitor(app.applicationContext)

    init {
        cellMonitor.start()
        viewModelScope.launch {
            cellMonitor.flow.collect { snap -> updateCellMetrics(snap) }
        }
    }

    override fun onCleared() {
        super.onCleared()
        cellMonitor.stop()
    }

    // ----- Engine toggle -----

    fun toggleEngine(active: Boolean) {
        val ctx = getApplication<Application>().applicationContext
        val intent = Intent(ctx, RnetForegroundService::class.java).apply {
            action = if (active) RnetForegroundService.ACTION_START
                     else        RnetForegroundService.ACTION_STOP
        }
        if (active) ctx.startForegroundService(intent)
        else        ctx.startService(intent)

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
}
