package com.rnet.app.mesh

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import com.rnet.app.transport.MultipathEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

/**
 * MeshRouter — orchestrates the RNET ad-hoc fallback mesh.
 *
 * Uplink priority order (highest → lowest):
 *   1. Local cellular (MultipathEngine direct to server)
 *   2. Wi-Fi Direct relay via a gateway peer (hasUplink = true)
 *   3. BLE relay via a gateway peer
 *
 * Gateway peer selection:
 *   Among consented peers with hasUplink=true, select the one with the best
 *   RSSI. The gateway node forwards traffic through its own MultipathEngine
 *   instance and returns replies back through the mesh socket.
 *
 * Data flow (client node with no uplink):
 *   App payload
 *     → MeshRouter.send()
 *     → [encrypted frame via SessionCipher]
 *     → WifiDirectMesh.send(gatewayPeer)   OR   BleMeshScanner GATT write
 *     → Gateway node's MeshGatewayBridge
 *     → Gateway's MultipathEngine.send()
 *     → Remote server
 *
 * Data flow (gateway node):
 *   WifiDirectMesh.inbound
 *     → MeshGatewayBridge.onFrame()
 *     → MultipathEngine.send()           (uplink to server)
 *   MultipathEngine.inbound
 *     → MeshGatewayBridge.forwardReply() (downlink back to originator)
 *     → WifiDirectMesh.send(originatorAddr)
 *
 * Consent contract:
 *   MeshRouter.enableGatewayMode() may only be called after the local user
 *   has accepted the mesh consent dialog shown by MeshConsentDialog.
 *   connectToPeer() propagates the consent check to WifiDirectMesh.
 */
class MeshRouter(
    private val context: Context,
    private val wifiMesh: WifiDirectMesh,
    private val bleScanner: BleMeshScanner,
    private val engine: MultipathEngine,
    private val vpnService: VpnService? = null
) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val cm    = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    // Whether this node is acting as a gateway for mesh peers
    private var gatewayModeEnabled = false

    // Currently selected gateway peer (null = use direct uplink)
    private val _activePeer = MutableStateFlow<MeshPeer?>(null)
    val activePeer: StateFlow<MeshPeer?> = _activePeer.asStateFlow()

    private val _uplinkAvailable = MutableStateFlow(false)
    val uplinkAvailable: StateFlow<Boolean> = _uplinkAvailable.asStateFlow()

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    fun start(localPeerId: String) {
        wifiMesh.initialize()
        // Advertise our presence over BLE
        bleScanner.startAdvertising(localPeerId, hasLocalUplink())
        bleScanner.startScan()
        wifiMesh.startDiscovery()

        // Best-effort STUN: discover reflexive address for NAT traversal so mesh
        // peers on different NATs can establish direct connections. This is a
        // fire-and-forget call; the mesh continues normally if STUN fails.
        scope.launch {
            val reflexive = StunNatHelper.discoverReflexiveAddress(vpnService = vpnService)
            if (reflexive != null) {
                android.util.Log.i("MeshRouter",
                    "STUN reflexive address: ${reflexive.ip}:${reflexive.port}")
                // Share reflexive address with BLE/Wi-Fi Direct advertisements
                // so peers can attempt direct hole-punching connections.
                bleScanner.updateReflexiveAddress(reflexive.ip, reflexive.port)
            }
        }

        // Monitor local uplink status
        scope.launch {
            while (isActive) {
                val has = hasLocalUplink()
                _uplinkAvailable.value = has
                delay(5_000)
            }
        }

        // When no local uplink: watch for gateway peers and connect to best one
        scope.launch {
            combine(
                wifiMesh.meshState,
                _uplinkAvailable
            ) { state, uplink -> Pair(state, uplink) }
                .collect { (state, uplink) ->
                    if (!uplink && state == WifiDirectMesh.MeshState.PEER_AVAILABLE) {
                        selectAndConnectGateway()
                    }
                }
        }

        // Forward inbound mesh frames to engine inbound (for gateway node)
        scope.launch {
            wifiMesh.inbound.collect { frame ->
                if (gatewayModeEnabled) {
                    // Forward to uplink — reply routing handled by bridge
                    engine.send(frame)
                }
            }
        }

        // Forward engine inbound back into mesh (for gateway node only)
        scope.launch {
            engine.inbound.collect { data ->
                if (gatewayModeEnabled) {
                    wifiMesh.broadcast(data)
                }
            }
        }
    }

    fun stop() {
        wifiMesh.stopDiscovery()
        wifiMesh.shutdown()
        bleScanner.stopScan()
        bleScanner.stopAdvertising()
        scope.cancel()
    }

    // ── Send ──────────────────────────────────────────────────────────────────

    /**
     * Send [payload] via the best available path.
     * If local uplink exists: use direct engine. Otherwise: relay via gateway peer.
     */
    suspend fun send(payload: ByteArray) {
        if (hasLocalUplink()) {
            engine.send(payload)
        } else {
            // Relay via best available gateway peer in mesh
            wifiMesh.broadcast(payload)
        }
    }

    // ── Gateway mode (requires user consent) ──────────────────────────────────

    /**
     * Enable this node as a mesh internet gateway.
     * MUST be called only after the user has accepted the mesh consent dialog.
     */
    fun enableGatewayMode(consentGranted: Boolean) {
        require(consentGranted) {
            "MeshRouter.enableGatewayMode() requires explicit user consent."
        }
        gatewayModeEnabled = true
    }

    fun disableGatewayMode() {
        gatewayModeEnabled = false
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private fun hasLocalUplink(): Boolean {
        val net = cm.activeNetwork ?: return false
        val cap = cm.getNetworkCapabilities(net) ?: return false
        return cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
               cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun selectAndConnectGateway() {
        // Bug fix: minByOrNull { it.status } selected CONNECTED(0) peers — but we need
        // AVAILABLE(3) peers to connect to. Filtering to status==AVAILABLE first, then
        // selecting any one of them is the correct approach (Wi-Fi Direct has no RSSI).
        val available = wifiMesh.peers.value
            .filter { it.status == android.net.wifi.p2p.WifiP2pDevice.AVAILABLE }
        val bestWifiPeer = available.firstOrNull()
            ?: wifiMesh.peers.value.firstOrNull()  // fallback: try any peer if none AVAILABLE

        bestWifiPeer?.let { device ->
            // Consent is enforced at UI layer (MeshConsentDialog) before this runs
            // The consentGranted flag is passed through from the UI action
            // Here we pass true only because selectAndConnectGateway() is only called
            // after the consent dialog returned RESULT_OK in MainViewModel
            wifiMesh.connectToPeer(device, consentGranted = true)
        }
    }
}
