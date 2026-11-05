package com.rnet.app.transport

import android.content.Context
import android.util.Log
import ca.psiphon.PsiphonTunnel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONObject

/**
 * PsiphonTransport — wraps the Psiphon tunnel-core SDK.
 *
 * This transport is used **only** when the user explicitly enables
 * "Route via Resilient Core" in the UI, clearly disclosing that traffic
 * will be routed through the Psiphon decentralized network.
 *
 * Psiphon is an open-source (GPL v3) censorship-circumvention tool operated
 * by Psiphon Inc., a Canadian non-profit.
 * Source: https://github.com/Psiphon-Labs/psiphon-tunnel-core
 *
 * When active, the Psiphon tunnel provides a local SOCKS5 proxy at
 * 127.0.0.1:[socksPort]. The MultipathEngine routes its upstream connection
 * through this proxy when the tunnel is established and "Resilient Core" is on.
 *
 * License note: psiphon-tunnel-core is GPL v3. Including it in RNET requires
 * RNET to also be distributed under GPL v3 when this module is compiled in.
 * See LICENSE in the repository root.
 */
class PsiphonTransport(private val context: Context) : PsiphonTunnel.HostService {

    private val TAG = "PsiphonTransport"

    enum class State { STOPPED, CONNECTING, CONNECTED, ERROR }

    private val _state = MutableStateFlow(State.STOPPED)
    val state: StateFlow<State> = _state

    /** SOCKS5 proxy port exposed by the Psiphon tunnel (0 = not yet assigned). */
    private var socksProxyPort = 0

    private val tunnel: PsiphonTunnel = PsiphonTunnel.newPsiphonTunnel(this)

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    /**
     * Starts the Psiphon tunnel. Blocks until the first server is connected,
     * then returns the SOCKS5 proxy address the tunnel exposes locally.
     *
     * Call from a background coroutine.
     */
    @Throws(Exception::class)
    fun start(): String {
        _state.value = State.CONNECTING
        tunnel.startTunneling(buildConfig())
        // startTunneling is synchronous up to connection establishment
        return "socks5://127.0.0.1:$socksProxyPort"
    }

    fun stop() {
        tunnel.stopTunneling()
        _state.value = State.STOPPED
        socksProxyPort = 0
    }

    // ── PsiphonTunnel.HostService callbacks ────────────────────────────────────

    override fun getPsiphonConfig(): String = buildConfig()

    override fun onDiagnosticMessage(message: String) {
        Log.d(TAG, "diagnostic: $message")
    }

    override fun onAvailableEgressRegions(regions: List<String>) {
        Log.d(TAG, "egress regions: $regions")
    }

    override fun onSocksProxyPortInUse(port: Int) {
        Log.w(TAG, "SOCKS port $port in use, retrying")
    }

    override fun onHttpProxyPortInUse(port: Int) {
        Log.w(TAG, "HTTP proxy port $port in use, retrying")
    }

    override fun onListeningSocksProxyPort(port: Int) {
        socksProxyPort = port
        Log.i(TAG, "SOCKS5 proxy on port $port")
    }

    override fun onListeningHttpProxyPort(port: Int) {
        Log.d(TAG, "HTTP proxy on port $port")
    }

    override fun onUpstreamProxyError(message: String) {
        Log.e(TAG, "upstream proxy error: $message")
    }

    override fun onConnecting() {
        _state.value = State.CONNECTING
        Log.i(TAG, "connecting…")
    }

    override fun onConnected() {
        _state.value = State.CONNECTED
        Log.i(TAG, "connected via Psiphon (SOCKS5 port $socksProxyPort)")
    }

    override fun onHomepage(url: String) {}

    override fun onSessionId(sessionId: String) {
        Log.d(TAG, "session: $sessionId")
    }

    override fun onClientRegion(region: String) {
        Log.d(TAG, "client region: $region")
    }

    override fun onClientUpgradeDownloaded(filename: String) {}

    override fun onClientIsLatestVersion() {}

    override fun onSplitTunnelRegion(region: String) {}

    override fun onUntunneledAddress(address: String) {}

    override fun onBytesTransferred(sent: Long, received: Long) {}

    override fun onStartedWaitingForNetworkConnectivity() {
        Log.w(TAG, "waiting for network connectivity")
    }

    override fun onStoppedWaitingForNetworkConnectivity() {}

    override fun onActiveAuthorizationIDs(authorizations: List<String>) {}

    override fun onExiting() {
        _state.value = State.STOPPED
    }

    override fun onServerAlert(actionURLs: List<String>) {}

    override fun onApplicationParameters(parameters: Any) {}

    override fun onInproxyProxyActivity(connectingClients: Int, connectedClients: Int,
                                        bytesUp: Long, bytesDown: Long) {}

    // ── Config ─────────────────────────────────────────────────────────────────

    /**
     * Minimal Psiphon config. No sponsor ID or propagation channel ID are
     * required for the public tunnel. The SDK downloads server lists
     * from Psiphon's directory authority on first connection.
     */
    private fun buildConfig(): String = JSONObject().apply {
        put("PropagationChannelId", "FFFFFFFFFFFFFFFF")
        put("SponsorId", "FFFFFFFFFFFFFFFF")
        put("DataRootDirectory",
            context.getDir("psiphon_data", Context.MODE_PRIVATE).absolutePath)
        // Allow the SDK to discover its own local proxy ports
        put("LocalSocksProxyPort", 0)
        put("LocalHttpProxyPort",  0)
        // Egress region: empty string = use nearest available node
        put("EgressRegion", "")
        // Disable in-proxy (we are not volunteering as a relay for others)
        put("InproxyEnableProxy", false)
    }.toString()
}
