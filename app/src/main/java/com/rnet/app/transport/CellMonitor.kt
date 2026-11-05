package com.rnet.app.transport

import android.content.Context
import android.telephony.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * CellMonitor — listens to Android TelephonyManager cell-info callbacks and
 * exposes a coroutine Flow of [CellSnapshot] objects for the transport engine.
 *
 * Uses only public API (TelephonyManager, CellInfo, CellSignalStrength subtypes).
 * No hidden APIs, no reflection. Requires ACCESS_FINE_LOCATION at runtime.
 *
 * CellSnapshot.rsrpDbm is used by MultipathEngine to prefer low-band cells
 * (Band 12/17/71/28 — 700–900 MHz) which have superior in-building penetration
 * during signal degradation, and to adjust MTU micro-framing thresholds.
 */
data class CellSnapshot(
    val subscriptionId: Int,
    val bandMhz: Int,          // Approximate carrier frequency (MHz); 0 = unknown
    val rsrpDbm: Int,          // Reference Signal Received Power (LTE/NR); dBm
    val rsrqDb: Int,           // Reference Signal Received Quality; dB
    val isLowBand: Boolean,    // True if 700–960 MHz (penetration-optimised)
    val technology: String,    // "LTE", "NR", "UMTS", "GSM"
)

class CellMonitor(private val context: Context) {

    private val telephonyManager =
        context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

    private val _flow = MutableSharedFlow<CellSnapshot>(
        replay = 1,
        extraBufferCapacity = 8,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val flow: SharedFlow<CellSnapshot> = _flow.asSharedFlow()

    private val callback = object : PhoneStateListener() {
        @Suppress("OVERRIDE_DEPRECATION")
        override fun onCellInfoChanged(cellInfoList: List<CellInfo>?) {
            cellInfoList?.forEach { parseCellInfo(it) }
        }
    }

    // TelephonyCallback for API 31+
    private val callback31: TelephonyCallback? by lazy {
        if (android.os.Build.VERSION.SDK_INT >= 31) {
            object : TelephonyCallback(), TelephonyCallback.CellInfoListener {
                override fun onCellInfoChanged(cellInfoList: MutableList<CellInfo>) {
                    cellInfoList.forEach { parseCellInfo(it) }
                }
            }
        } else null
    }

    fun start() {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 31 && callback31 != null) {
                telephonyManager.registerTelephonyCallback(
                    context.mainExecutor,
                    callback31!!
                )
            } else {
                @Suppress("DEPRECATION")
                telephonyManager.listen(callback, PhoneStateListener.LISTEN_CELL_INFO)
            }
            // Initial snapshot
            try {
                telephonyManager.allCellInfo?.forEach { parseCellInfo(it) }
            } catch (_: SecurityException) {}
        } catch (_: SecurityException) {
            // READ_PHONE_STATE not granted — cell monitoring unavailable, continue without it
        } catch (_: Exception) {
            // Any other telephony error — continue without cell monitoring
        }
    }

    fun stop() {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 31 && callback31 != null) {
                telephonyManager.unregisterTelephonyCallback(callback31!!)
            } else {
                @Suppress("DEPRECATION")
                telephonyManager.listen(callback, PhoneStateListener.LISTEN_NONE)
            }
        } catch (_: Exception) {}
    }

    private fun parseCellInfo(info: CellInfo) {
        val snapshot: CellSnapshot = when (info) {
            is CellInfoLte -> {
                val ss = info.cellSignalStrength
                val id = info.cellIdentity
                val freqMhz = if (android.os.Build.VERSION.SDK_INT >= 30) {
                    id.bands.firstOrNull()?.let { bandToMhz(it) } ?: 0
                } else 0
                CellSnapshot(
                    subscriptionId = info.cellIdentity.mccString?.let { 0 } ?: 0,
                    bandMhz = freqMhz,
                    rsrpDbm = ss.rsrp,
                    rsrqDb  = ss.rsrq,
                    isLowBand = freqMhz in 700..960,
                    technology = "LTE"
                )
            }
            is CellInfoNr -> {
                val ss = info.cellSignalStrength as CellSignalStrengthNr
                val id = info.cellIdentity as CellIdentityNr
                val freqMhz = if (android.os.Build.VERSION.SDK_INT >= 30) {
                    id.bands.firstOrNull()?.let { bandToMhz(it) } ?: 0
                } else 0
                CellSnapshot(
                    subscriptionId = 0,
                    bandMhz = freqMhz,
                    rsrpDbm = ss.ssRsrp,
                    rsrqDb  = ss.ssRsrq,
                    isLowBand = freqMhz in 700..960,
                    technology = "NR"
                )
            }
            is CellInfoWcdma -> {
                val ss = info.cellSignalStrength
                CellSnapshot(
                    subscriptionId = 0,
                    bandMhz = 0,
                    rsrpDbm = ss.dbm,
                    rsrqDb  = -1,
                    isLowBand = false,
                    technology = "UMTS"
                )
            }
            is CellInfoGsm -> {
                val ss = info.cellSignalStrength
                CellSnapshot(
                    subscriptionId = 0,
                    bandMhz = 0,
                    rsrpDbm = ss.dbm,
                    rsrqDb  = -1,
                    isLowBand = false,
                    technology = "GSM"
                )
            }
            else -> return
        }
        _flow.tryEmit(snapshot)
    }

    // LTE/NR band → approximate center frequency in MHz
    private fun bandToMhz(band: Int): Int = when (band) {
        12, 13, 17 -> 750    // 700 MHz
        14         -> 758
        28         -> 758    // APT 700
        20         -> 800    // EU 800
        5, 6, 19   -> 850    // 850 MHz
        26         -> 850
        8          -> 900    // 900 MHz
        71         -> 663    // T-Mobile 600
        29         -> 717
        18         -> 850
        else       -> 0
    }
}
