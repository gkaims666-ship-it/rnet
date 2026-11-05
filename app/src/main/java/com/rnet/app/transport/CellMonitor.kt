package com.rnet.app.transport

import android.content.Context
import android.os.Build
import android.telephony.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.concurrent.atomic.AtomicBoolean

/**
 * CellMonitor — listens to Android TelephonyManager cell-info callbacks and
 * exposes a coroutine Flow of [CellSnapshot] objects for the transport engine.
 *
 * Thread-safe: start()/stop() may be called from any thread.
 * Idempotent: calling start() twice, or stop() twice, is safe.
 */
data class CellSnapshot(
    val subscriptionId: Int,
    val bandMhz: Int,
    val rsrpDbm: Int,
    val rsrqDb: Int,
    val isLowBand: Boolean,
    val technology: String,
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

    // Atomic flag prevents double-registration regardless of which thread calls start()
    private val registered = AtomicBoolean(false)

    // Legacy listener (API < 31)
    private val legacyCallback = object : PhoneStateListener() {
        @Suppress("OVERRIDE_DEPRECATION")
        override fun onCellInfoChanged(cellInfoList: List<CellInfo>?) {
            cellInfoList?.forEach { parseCellInfo(it) }
        }
    }

    // Modern callback (API 31+) — created lazily, only on API 31+
    private val modernCallback: TelephonyCallback? by lazy {
        if (Build.VERSION.SDK_INT >= 31) {
            object : TelephonyCallback(), TelephonyCallback.CellInfoListener {
                override fun onCellInfoChanged(cellInfoList: MutableList<CellInfo>) {
                    cellInfoList.forEach { parseCellInfo(it) }
                }
            }
        } else null
    }

    /**
     * Start cell monitoring. Idempotent — safe to call multiple times.
     * Silently no-ops if READ_PHONE_STATE is not granted.
     */
    fun start() {
        if (!registered.compareAndSet(false, true)) return  // already registered

        try {
            if (Build.VERSION.SDK_INT >= 31) {
                val cb = modernCallback
                if (cb != null) {
                    telephonyManager.registerTelephonyCallback(context.mainExecutor, cb)
                } else {
                    @Suppress("DEPRECATION")
                    telephonyManager.listen(legacyCallback, PhoneStateListener.LISTEN_CELL_INFO)
                }
            } else {
                @Suppress("DEPRECATION")
                telephonyManager.listen(legacyCallback, PhoneStateListener.LISTEN_CELL_INFO)
            }
            // Emit initial snapshot if available
            try {
                telephonyManager.allCellInfo?.forEach { parseCellInfo(it) }
            } catch (_: SecurityException) {}
        } catch (_: SecurityException) {
            // READ_PHONE_STATE not granted — cell monitoring unavailable
            registered.set(false)  // allow retry after permission grant
        } catch (_: Exception) {
            registered.set(false)
        }
    }

    /**
     * Stop cell monitoring. Idempotent — safe to call multiple times.
     */
    fun stop() {
        if (!registered.compareAndSet(true, false)) return  // already unregistered

        try {
            if (Build.VERSION.SDK_INT >= 31) {
                val cb = modernCallback
                if (cb != null) {
                    telephonyManager.unregisterTelephonyCallback(cb)
                } else {
                    @Suppress("DEPRECATION")
                    telephonyManager.listen(legacyCallback, PhoneStateListener.LISTEN_NONE)
                }
            } else {
                @Suppress("DEPRECATION")
                telephonyManager.listen(legacyCallback, PhoneStateListener.LISTEN_NONE)
            }
        } catch (_: Exception) {}
    }

    private fun parseCellInfo(info: CellInfo) {
        val snapshot: CellSnapshot = when (info) {
            is CellInfoLte -> {
                val ss = info.cellSignalStrength
                val id = info.cellIdentity
                val freqMhz = if (Build.VERSION.SDK_INT >= 30) {
                    id.bands.firstOrNull()?.let { bandToMhz(it) } ?: 0
                } else 0
                CellSnapshot(
                    subscriptionId = 0,
                    bandMhz   = freqMhz,
                    rsrpDbm   = ss.rsrp,
                    rsrqDb    = ss.rsrq,
                    isLowBand = freqMhz in 700..960,
                    technology = "LTE"
                )
            }
            is CellInfoNr -> {
                val ss = info.cellSignalStrength as CellSignalStrengthNr
                val id = info.cellIdentity as CellIdentityNr
                val freqMhz = if (Build.VERSION.SDK_INT >= 30) {
                    id.bands.firstOrNull()?.let { bandToMhz(it) } ?: 0
                } else 0
                CellSnapshot(
                    subscriptionId = 0,
                    bandMhz   = freqMhz,
                    rsrpDbm   = ss.ssRsrp,
                    rsrqDb    = ss.ssRsrq,
                    isLowBand = freqMhz in 700..960,
                    technology = "NR"
                )
            }
            is CellInfoWcdma -> CellSnapshot(
                subscriptionId = 0, bandMhz = 0,
                rsrpDbm = info.cellSignalStrength.dbm,
                rsrqDb = -1, isLowBand = false, technology = "UMTS"
            )
            is CellInfoGsm -> CellSnapshot(
                subscriptionId = 0, bandMhz = 0,
                rsrpDbm = info.cellSignalStrength.dbm,
                rsrqDb = -1, isLowBand = false, technology = "GSM"
            )
            else -> return
        }
        _flow.tryEmit(snapshot)
    }

    private fun bandToMhz(band: Int): Int = when (band) {
        12, 13, 17 -> 750; 14 -> 758; 28 -> 758; 20 -> 800
        5, 6, 19   -> 850; 26 -> 850; 8 -> 900; 71 -> 663; 29 -> 717; 18 -> 850
        else -> 0
    }
}
