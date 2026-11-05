package com.rnet.shared.mesh

/**
 * Platform-agnostic model for a discovered mesh peer.
 * Shared between Android (Wi-Fi Direct + BLE) and iOS (MultipeerConnectivity).
 */
data class MeshPeer(
    val peerId: String,
    val displayName: String,
    /** Physical address hint — MAC on Android, MCPeerID.displayName on iOS */
    val addressHint: String,
    val hasUplink: Boolean,
    /** Received signal strength in dBm (or Int.MIN_VALUE if unknown) */
    val rssi: Int,
    val transportType: TransportType,
    val consentState: ConsentState
) {
    /** True when this peer can serve as a relay gateway */
    val isGatewayCandidate: Boolean
        get() = hasUplink && consentState == ConsentState.GRANTED
}

enum class TransportType {
    WIFI_DIRECT,   // Android Wi-Fi P2P
    BLE,           // Android BLE manufacturer advertisement
    MULTIPEER,     // iOS MultipeerConnectivity (Wi-Fi + Bluetooth + Infrastructure)
    UNKNOWN
}

enum class ConsentState { PENDING, GRANTED, DENIED }
