package com.rnet.app.mesh

/**
 * MeshPeer — immutable descriptor for a discovered RNET peer node.
 *
 * @param peerId          Stable 128-bit random ID generated once at install and persisted.
 *                        Used to deduplicate peers across discovery restarts.
 * @param displayName     Human-readable label shown in the consent dialog ("RNET-node-7F3A").
 * @param macAddress      Wi-Fi Direct device MAC (Wi-Fi P2P) or empty string for BLE-only peers.
 * @param bleAddress      BLE device address or empty string for Wi-Fi Direct-only peers.
 * @param hasUplink       True when the peer has confirmed active cellular connectivity and
 *                        is willing to act as a mesh gateway.
 * @param rssi            Signal strength indicator (dBm); -100 = weakest usable.
 * @param transportType   Primary transport used to reach this peer.
 * @param consentState    Tracks whether the local user has opted in to routing via this peer.
 */
data class MeshPeer(
    val peerId: String,
    val displayName: String,
    val macAddress: String,
    val bleAddress: String,
    val hasUplink: Boolean,
    val rssi: Int,
    val transportType: TransportType,
    val consentState: ConsentState = ConsentState.PENDING
) {
    enum class TransportType { WIFI_DIRECT, BLE, BOTH }
    enum class ConsentState  { PENDING, GRANTED, DENIED }

    /** True if this peer can serve as an upstream gateway for the mesh cluster. */
    val isGatewayCandidate: Boolean get() = hasUplink && consentState == ConsentState.GRANTED
}
