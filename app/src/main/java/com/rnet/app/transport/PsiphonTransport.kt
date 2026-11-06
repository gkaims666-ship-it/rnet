package com.rnet.app.transport

import android.content.Context
import android.util.Log
import ca.psiphon.PsiphonTunnel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.CompletableDeferred
import org.json.JSONObject

/**
 * PsiphonTransport — wraps the Psiphon tunnel-core SDK.
 *
 * Used ONLY when the user explicitly enables "Route via Resilient Core" in the UI,
 * clearly disclosing that traffic will be routed through the Psiphon network.
 *
 * Psiphon is an open-source (GPL v3) censorship-circumvention tool operated
 * by Psiphon Inc., a Canadian non-profit.
 * Source: https://github.com/Psiphon-Labs/psiphon-tunnel-core
 *
 * When active, the tunnel provides a local SOCKS5 proxy at 127.0.0.1:[socksPort].
 * The MultipathEngine routes its upstream connection through this proxy.
 *
 * License note: psiphon-tunnel-core is GPL v3. Including it requires RNET to be
 * distributed under GPL v3 when this module is compiled in.
 * See LICENSE in the repository root.
 */
class PsiphonTransport(
    private val context: Context,
    /** Psiphon egress region code, e.g. "NL", "DE", "US", "" = fastest */
    private val egressRegion: String = "NL"
) : PsiphonTunnel.HostService {

    private val TAG = "PsiphonTransport"

    enum class State { STOPPED, CONNECTING, CONNECTED, ERROR }

    private val _state = MutableStateFlow(State.STOPPED)
    val state: StateFlow<State> = _state

    /** SOCKS5 proxy port exposed by the Psiphon tunnel (0 = not yet assigned). */
    @Volatile private var socksProxyPort = 0

    /** Signals when the first SOCKS port has been assigned by the callback. */
    private var portReady: CompletableDeferred<Int> = CompletableDeferred()

    private val tunnel: PsiphonTunnel = PsiphonTunnel.newPsiphonTunnel(this)

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    /**
     * Starts the Psiphon tunnel. Blocks until the SOCKS5 port is assigned
     * (i.e. until [onListeningSocksProxyPort] fires), then returns the proxy address.
     * Times out after 60 seconds and throws if the port was never assigned.
     * Call from a background coroutine / worker thread.
     */
    @Throws(Exception::class)
    fun start(): String {
        // Reset deferred so a re-start after stop() works correctly
        portReady = CompletableDeferred()
        socksProxyPort = 0
        _state.value = State.CONNECTING
        tunnel.startTunneling("")
        // Block here until onListeningSocksProxyPort fires (or timeout)
        val port = runBlocking {
            withTimeoutOrNull(60_000L) { portReady.await() }
        } ?: throw Exception("Psiphon SOCKS port not assigned within 60 s")
        return "socks5://127.0.0.1:$port"
    }

    fun stop() {
        tunnel.stop()
        _state.value = State.STOPPED
        socksProxyPort = 0
        // Cancel any pending waiters so a stalled start() can unblock
        if (!portReady.isCompleted) portReady.cancel()
    }

    // ── PsiphonTunnel.HostService — required methods ───────────────────────────

    override fun getContext(): Context = context

    override fun getPsiphonConfig(): String = buildConfig()

    // ── PsiphonTunnel.HostService — optional callbacks ─────────────────────────

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
        portReady.complete(port)   // unblock start()
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

    override fun onClientRegion(region: String) {
        Log.d(TAG, "client region: $region")
    }

    override fun onClientUpgradeDownloaded(filename: String) {}

    override fun onClientIsLatestVersion() {}

    override fun onSplitTunnelRegions(regions: List<String>) {}

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

    override fun onApplicationParameters(parameters: Any) {}

    override fun onServerAlert(reason: String, subject: String, actionURLs: List<String>) {
        Log.w(TAG, "server alert: $reason / $subject")
    }

    override fun onInproxyProxyActivity(
        announcing: Int,
        connectingClients: Int,
        connectedClients: Int,
        bytesUp: Long,
        bytesDown: Long,
        personalRegionActivity: Map<String, PsiphonTunnel.RegionActivitySnapshot>,
        commonRegionActivity: Map<String, PsiphonTunnel.RegionActivitySnapshot>
    ) {}

    // ── Config ─────────────────────────────────────────────────────────────────

    private fun buildConfig(): String = JSONObject().apply {
        put("PropagationChannelId", "24BCA4EE20BEB92C")
        put("SponsorId", "721AE60D76700F5A")
        put("DataRootDirectory",
            context.getDir("psiphon_data", Context.MODE_PRIVATE).absolutePath)
        put("LocalSocksProxyPort", 0)
        put("LocalHttpProxyPort",  0)
        put("EgressRegion", egressRegion)       // location masking: exit in chosen country
        put("InproxyEnableProxy", false)
        // Speed tuning
        put("ConnectionWorkerPoolSize", 10)     // parallel tunnel connection attempts
        put("TunnelProtocolOrder",              // prefer fast protocols first
            org.json.JSONArray().apply {
                put("OSSH"); put("SSH"); put("FRONTED-MEEK-OSSH"); put("FRONTED-MEEK")
            })
        put("NetworkLatencyMultiplier", 1.0)    // don't add extra latency
    }.toString()
}
