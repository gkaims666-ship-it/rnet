package com.rnet.app.mesh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.NetworkInfo
import android.net.wifi.p2p.*
import android.os.Build
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import java.io.*
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * WifiDirectMesh — Wi-Fi P2P (Wi-Fi Direct) discovery, group formation, and
 * inter-node data relay for the RNET mesh fallback layer.
 *
 * State machine:
 *
 *   IDLE ──startDiscovery()──► DISCOVERING
 *        ◄──stopDiscovery()───
 *   DISCOVERING ──peer found──► PEER_AVAILABLE   (emits peerDiscovered event)
 *   PEER_AVAILABLE ──user grants consent──► CONNECTING
 *   CONNECTING ──P2P group formed──► CONNECTED
 *   CONNECTED ──link lost──► DISCOVERING  (auto-restart)
 *
 * Data plane:
 *   Group Owner (GO) listens on TCP port [DATA_PORT].
 *   Group Client connects to GO's IP from WifiP2pInfo.groupOwnerAddress.
 *   All frames are encrypted before hand-off to this layer by the caller
 *   (MultipathEngine or MeshRouter).
 *
 * Consent gate:
 *   connectToPeer() throws IllegalStateException if [peer.consentState] ≠ GRANTED.
 *   The UI must call this only after the consent dialog returns RESULT_OK.
 *
 * Required permissions (declared in AndroidManifest, requested at runtime):
 *   ACCESS_FINE_LOCATION (API ≤ 32), NEARBY_WIFI_DEVICES (API 33+)
 *   CHANGE_WIFI_STATE, ACCESS_WIFI_STATE
 */
class WifiDirectMesh(private val context: Context) {

    companion object {
        const val DATA_PORT      = 8765
        const val SERVICE_TYPE   = "_rnet._tcp"
        const val SERVICE_NAME   = "rnet-mesh"
        const val INSTANCE_EXTRA = "rnet-peer-id"
    }

    // ── Public state ──────────────────────────────────────────────────────────

    private val _peers = MutableStateFlow<List<WifiP2pDevice>>(emptyList())
    val peers: StateFlow<List<WifiP2pDevice>> = _peers.asStateFlow()

    private val _connectionInfo = MutableStateFlow<WifiP2pInfo?>(null)
    val connectionInfo: StateFlow<WifiP2pInfo?> = _connectionInfo.asStateFlow()

    private val _meshState = MutableStateFlow(MeshState.IDLE)
    val meshState: StateFlow<MeshState> = _meshState.asStateFlow()

    private val _inbound = MutableSharedFlow<ByteArray>(
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val inbound: SharedFlow<ByteArray> = _inbound.asSharedFlow()

    enum class MeshState { IDLE, DISCOVERING, PEER_AVAILABLE, CONNECTING, CONNECTED }

    // ── Internal ──────────────────────────────────────────────────────────────

    private val manager: WifiP2pManager =
        context.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
    private lateinit var channel: WifiP2pManager.Channel
    private val scope   = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val sockets = ConcurrentHashMap<String, Socket>()
    private var serverSocket: ServerSocket? = null
    private var isGroupOwner = false

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    fun initialize() {
        channel = manager.initialize(context, context.mainLooper, null)
        context.registerReceiver(p2pReceiver, intentFilter())
    }

    fun shutdown() {
        if (::channel.isInitialized) {
            stopDiscovery()
        }
        sockets.values.forEach { runCatching { it.close() } }
        serverSocket?.close()
        try { context.unregisterReceiver(p2pReceiver) } catch (_: Exception) {}
        scope.cancel()
    }

    // ── Discovery ─────────────────────────────────────────────────────────────

    fun startDiscovery() {
        if (!::channel.isInitialized) return
        _meshState.value = MeshState.DISCOVERING
        manager.discoverPeers(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {}
            override fun onFailure(reason: Int) {
                _meshState.value = MeshState.IDLE
            }
        })
    }

    fun stopDiscovery() {
        if (!::channel.isInitialized) return
        manager.stopPeerDiscovery(channel, null)
        _meshState.value = MeshState.IDLE
    }

    // ── Connection (requires prior consent from UI) ───────────────────────────

    /**
     * Connect to [device]. Caller MUST ensure the user has explicitly granted
     * consent in [MeshConsentDialog] before invoking this method.
     */
    fun connectToPeer(device: WifiP2pDevice, consentGranted: Boolean) {
        require(consentGranted) {
            "WifiDirectMesh.connectToPeer() called without user consent. " +
            "Show MeshConsentDialog first."
        }
        _meshState.value = MeshState.CONNECTING
        val config = WifiP2pConfig().apply { deviceAddress = device.deviceAddress }
        manager.connect(channel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {}
            override fun onFailure(reason: Int) {
                _meshState.value = MeshState.PEER_AVAILABLE
            }
        })
    }

    fun disconnect() {
        manager.removeGroup(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() { _meshState.value = MeshState.IDLE }
            override fun onFailure(reason: Int) {}
        })
    }

    // ── Data plane ────────────────────────────────────────────────────────────

    /** Send [data] to all currently connected peers. */
    fun broadcast(data: ByteArray) {
        sockets.values.forEach { socket ->
            scope.launch {
                try {
                    val out = DataOutputStream(socket.getOutputStream())
                    out.writeInt(data.size)
                    out.write(data)
                    out.flush()
                } catch (_: Exception) {}
            }
        }
    }

    /** Send [data] to a specific peer by device address. */
    fun send(deviceAddress: String, data: ByteArray) {
        val socket = sockets[deviceAddress] ?: return
        scope.launch {
            try {
                val out = DataOutputStream(socket.getOutputStream())
                out.writeInt(data.size)
                out.write(data)
                out.flush()
            } catch (_: Exception) {}
        }
    }

    // ── BroadcastReceiver (P2P state changes) ─────────────────────────────────

    private val p2pReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                    manager.requestPeers(channel) { peerList ->
                        val devices = peerList.deviceList.toList()
                        _peers.value = devices
                        if (devices.isNotEmpty() && _meshState.value == MeshState.DISCOVERING) {
                            _meshState.value = MeshState.PEER_AVAILABLE
                        }
                    }
                }
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    val networkInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO, NetworkInfo::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO) as? NetworkInfo
                    }
                    if (networkInfo?.isConnected == true) {
                        manager.requestConnectionInfo(channel) { info ->
                            _connectionInfo.value = info
                            isGroupOwner = info.isGroupOwner
                            _meshState.value = MeshState.CONNECTED
                            if (info.isGroupOwner) {
                                scope.launch { startGroupOwnerServer() }
                            } else {
                                scope.launch { connectAsClient(info.groupOwnerAddress.hostAddress ?: return@launch) }
                            }
                        }
                    } else {
                        _meshState.value = MeshState.DISCOVERING
                        startDiscovery()
                    }
                }
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val state = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1)
                    if (state == WifiP2pManager.WIFI_P2P_STATE_DISABLED) {
                        _meshState.value = MeshState.IDLE
                    }
                }
            }
        }
    }

    // ── Group Owner TCP server ────────────────────────────────────────────────

    private suspend fun startGroupOwnerServer() {
        serverSocket = ServerSocket(DATA_PORT)
        while (currentCoroutineContext().isActive) {
            try {
                val client = serverSocket!!.accept()
                val addr   = client.inetAddress.hostAddress ?: continue
                sockets[addr] = client
                scope.launch { receiveLoop(client, addr) }
            } catch (_: Exception) { break }
        }
    }

    // ── Client connection ─────────────────────────────────────────────────────

    private suspend fun connectAsClient(goAddress: String) {
        var retries = 0
        while (retries < 5 && currentCoroutineContext().isActive) {
            try {
                val socket = Socket(goAddress, DATA_PORT)
                sockets[goAddress] = socket
                scope.launch { receiveLoop(socket, goAddress) }
                return
            } catch (_: Exception) {
                retries++
                delay(1000L * retries)   // suspend instead of blocking Thread.sleep
            }
        }
    }

    // ── Receive loop (per socket) ─────────────────────────────────────────────

    private fun receiveLoop(socket: Socket, peerAddr: String) {
        val din = DataInputStream(socket.getInputStream())
        while (!socket.isClosed) {
            try {
                val len  = din.readInt()
                val data = ByteArray(len)
                din.readFully(data)
                scope.launch { _inbound.emit(data) }
            } catch (_: Exception) { break }
        }
        sockets.remove(peerAddr)
        if (sockets.isEmpty() && _meshState.value == MeshState.CONNECTED) {
            _meshState.value = MeshState.DISCOVERING
            startDiscovery()
        }
    }

    private fun intentFilter() = IntentFilter().apply {
        addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
    }
}
