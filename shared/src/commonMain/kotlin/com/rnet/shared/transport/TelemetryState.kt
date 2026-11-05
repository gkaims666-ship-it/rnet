package com.rnet.shared.transport

/**
 * Shared telemetry snapshot consumed by both the Android ViewModel
 * and the iOS ObservableObject / @Observable view model.
 *
 * Exposed from the KMP framework as a Kotlin data class; on iOS it is
 * observed via a Swift wrapper that publishes to @Published properties.
 */
data class TelemetryState(
    val engineActive: Boolean = false,
    /** Signal-to-noise ratio estimate (dB), 0 if unavailable */
    val snrDb: Float = 0f,
    /** Packet delivery rate [0.0, 1.0] */
    val packetDeliveryRate: Float = 1f,
    /** Radio access technology string, e.g. "NR", "LTE", "HSPA" */
    val technology: String = "",
    /** Center frequency of serving cell in MHz */
    val bandMhz: Int = 0,
    /** Whether the serving cell is a low-band cell (700–960 MHz) */
    val isLowBand: Boolean = false,
    /** Total bytes received across all paths */
    val totalBytesIn: Long = 0L,
    /** Total bytes sent across all paths */
    val totalBytesOut: Long = 0L,
    /** Current selected endpoint label */
    val activeEndpoint: String = "",
    /** Active mesh peers */
    val meshPeers: List<MeshPeerSnapshot> = emptyList(),
    /** Whether this device is acting as mesh gateway */
    val isGateway: Boolean = false
)

data class MeshPeerSnapshot(
    val displayName: String,
    val hasUplink: Boolean,
    val rssi: Int,
    val transport: String
)
