package com.rnet.app.gateway

import android.content.Context
import android.net.wifi.WifiManager
import com.rnet.app.transport.MultipathEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.InputStream
import java.io.OutputStream
import java.net.*
import java.util.concurrent.atomic.AtomicInteger

/**
 * HotspotGateway — a disclosed, consensual local routing gateway.
 *
 * CONSENT REQUIREMENT: This component MUST NOT be started without
 * [consentGranted] = true. The consent flag is set only after the user
 * explicitly accepts the full disclosure screen in [ConsentActivity].
 * The UI enforces this gate; this class enforces it again defensively.
 *
 * Architecture:
 *   Android Wi-Fi Hotspot (WifiManager softAP) ← connected peer devices
 *   ↓ TCP/UDP NAT proxy on 10.x.x.1 (gateway address)
 *   ↓ MultipathEngine (QUIC / multi-path UDP with FEC)
 *   ↓ Remote server
 *
 * Consent disclosure text (also shown in UI strings.xml):
 *   "RNET will route network traffic from devices connected to this hotspot
 *    through RNET's encrypted multi-path transport. Connected devices will
 *    use this Android device as a network gateway. You can stop this at any
 *    time by toggling the Gateway switch."
 *
 * BLIND GATEWAY — privacy by design:
 *   The gateway does NOT inspect, classify, or profile the traffic of connected
 *   peers. It keeps no per-peer records: no MAC/IP-derived keys, no OS
 *   fingerprinting (no User-Agent sniffing), no per-peer byte/latency/connection
 *   accounting. The only thing it measures is the aggregate bitrate across the
 *   whole interface (total bytes in/out), so the host can see that the bridge is
 *   doing something — never who is doing what. Peer bytes pass through a
 *   transparent relay into the encrypted transport and are never examined.
 */
class HotspotGateway(
    private val context: Context,
    private val engine: MultipathEngine?
) {

    // Retained for API/source compatibility with the UI layer. The gateway no
    // longer produces per-peer metrics, so the stations map is always empty.
    data class StationMetrics(
        val macHint: String,
        val osHint: String,
        val bytesIn: Long,
        val bytesOut: Long,
        val latencyMs: Long,
        val activeConns: Int
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Public state — always empty: the blind gateway keeps no per-peer records.
    private val _stations = MutableStateFlow<Map<String, StationMetrics>>(emptyMap())
    val stations: StateFlow<Map<String, StationMetrics>> = _stations

    // Aggregate interface throughput only — the one thing we measure.
    // Bug fix: StateFlow is not thread-safe for read-modify-write (`value += n`).
    // Use AtomicLong for concurrent byte counting; expose via StateFlow for UI.
    private val _totalBytesInAtomic  = java.util.concurrent.atomic.AtomicLong(0L)
    private val _totalBytesOutAtomic = java.util.concurrent.atomic.AtomicLong(0L)
    private val _totalBytesIn  = MutableStateFlow(0L)
    val totalBytesIn: StateFlow<Long> = _totalBytesIn

    private val _totalBytesOut = MutableStateFlow(0L)
    val totalBytesOut: StateFlow<Long> = _totalBytesOut

    // Consent gate — MUST be true before start()
    private var consentGranted = false

    // Only a live connection counter for aggregate throughput bookkeeping —
    // not keyed to any peer identity.
    private val activeConnections = AtomicInteger(0)

    private var proxyServer: ServerSocket? = null

    fun grantConsent() { consentGranted = true }

    /**
     * Start the gateway proxy.
     * Throws [SecurityException] if consent has not been granted.
     */
    fun start() {
        check(consentGranted) {
            "HotspotGateway requires explicit user consent. " +
            "Show the disclosure screen and call grantConsent() first."
        }

        // Listen for inbound connections from tethered clients (gateway address)
        // Android assigns 192.168.43.1 or 10.0.0.1 as the softAP gateway
        scope.launch {
            val serverSocket = try {
                ServerSocket(PROXY_PORT, 50, InetAddress.getByName("0.0.0.0"))
            } catch (e: Exception) {
                android.util.Log.e("HotspotGateway",
                    "Could not bind to port $PROXY_PORT: ${e.message}")
                return@launch
            }
            proxyServer = serverSocket
            while (isActive) {
                try {
                    val client = proxyServer!!.accept()
                    launch { handleClient(client) }
                } catch (_: Exception) { break }
            }
        }

        // Periodically publish metrics snapshot
        scope.launch {
            while (isActive) {
                delay(1000)
                publishMetrics()
            }
        }
    }

    fun stop() {
        proxyServer?.close()
        scope.cancel()
    }

    // ----- Per-client proxy handler -----

    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        activeConnections.incrementAndGet()
        try {
            val inStream  = client.getInputStream()
            val outStream = client.getOutputStream()

            // Drain the HTTP CONNECT header off the stream so the byte stream is
            // positioned at the tunnel payload. We do NOT inspect or parse it —
            // no host/port logging, no User-Agent or OS fingerprinting. The
            // encrypted transport handles routing; the gateway stays blind.
            if (!drainHttpConnectHeader(inStream)) return@withContext

            // ACK to client (HTTP CONNECT tunnel)
            outStream.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
            outStream.flush()

            // Relay: client → engine (outbound), engine.inbound → client (inbound)
            val relay = scope.launch { relay(inStream, outStream) }
            relay.join()
        } catch (_: Exception) {
        } finally {
            activeConnections.decrementAndGet()
            client.close()
        }
    }

    private suspend fun relay(
        clientIn: InputStream,
        clientOut: OutputStream
    ) {
        val buf = ByteArray(8192)
        // Forward client traffic through MultipathEngine. Count aggregate bytes
        // only — never attributed to a peer.
        val forward = scope.launch {
            while (true) {
                val n = try { clientIn.read(buf) } catch (_: Exception) { break }
                if (n <= 0) break
                val data = buf.copyOf(n)
                _totalBytesInAtomic.addAndGet(n.toLong())
                engine?.send(data)
            }
        }
        // Return traffic from engine to client.
        // Bug fix: when engine is null this coroutine would run forever collecting nothing.
        // Wrap in a check; also cancel forward when backward fails (e.g. client disconnected).
        val backward = if (engine != null) scope.launch {
            try {
                engine.inbound.collect { data ->
                    clientOut.write(data)
                    clientOut.flush()
                    _totalBytesOutAtomic.addAndGet(data.size.toLong())
                }
            } catch (_: Exception) {
                forward.cancel()
            }
        } else null
        forward.join()
        backward?.cancel()
    }

    // ----- Aggregate throughput only -----

    private fun publishMetrics() {
        // No per-peer snapshot is ever produced — stations stays empty.
        // Only the aggregate interface counters are flushed to the UI.
        _totalBytesIn.value  = _totalBytesInAtomic.get()
        _totalBytesOut.value = _totalBytesOutAtomic.get()
    }

    // ----- HTTP CONNECT header drain (no inspection) -----

    /**
     * Consume bytes up to and including the CONNECT header terminator (\r\n\r\n)
     * without retaining or parsing them. Returns false if the stream ended before
     * a header was seen.
     */
    private fun drainHttpConnectHeader(stream: InputStream): Boolean {
        var seen = false
        var s0 = -1; var s1 = -1; var s2 = -1
        val buf = ByteArray(1)
        while (stream.read(buf) == 1) {
            seen = true
            val c = buf[0].toInt()
            // Slide a 4-byte window looking for CR LF CR LF; nothing is stored.
            s0 = s1; s1 = s2; s2 = c
            if (s0 == '\r'.code && s1 == '\n'.code && s2 == '\r'.code) {
                // need one more \n
                if (stream.read(buf) == 1 && buf[0].toInt() == '\n'.code) return true
            }
        }
        return seen
    }

    companion object {
        const val PROXY_PORT = 8118  // User-visible in disclosure text
    }
}
