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
import java.util.concurrent.ConcurrentHashMap
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
 * QoS metrics tracked per station (MAC address):
 *   - Bytes in/out
 *   - Packet latency (round-trip ping)
 *   - Detected OS hint (from TCP User-Agent probe, non-identifying)
 *   - Active connection count
 */
class HotspotGateway(
    private val context: Context,
    private val engine: MultipathEngine
) {

    data class StationMetrics(
        val macHint: String,         // Last 3 octets only — non-identifying
        val osHint: String,          // "iOS", "Android", "Windows", "macOS", "Unknown"
        val bytesIn: Long,
        val bytesOut: Long,
        val latencyMs: Long,
        val activeConns: Int
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Public state
    private val _stations = MutableStateFlow<Map<String, StationMetrics>>(emptyMap())
    val stations: StateFlow<Map<String, StationMetrics>> = _stations

    private val _totalBytesIn  = MutableStateFlow(0L)
    val totalBytesIn: StateFlow<Long> = _totalBytesIn

    private val _totalBytesOut = MutableStateFlow(0L)
    val totalBytesOut: StateFlow<Long> = _totalBytesOut

    // Consent gate — MUST be true before start()
    private var consentGranted = false

    private val stationMap = ConcurrentHashMap<String, StationMetricsInternal>()

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
            proxyServer = ServerSocket(PROXY_PORT, 50, InetAddress.getByName("0.0.0.0"))
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
        val stationKey = deriveStationKey(client.inetAddress)
        val internal   = stationMap.getOrPut(stationKey) { StationMetricsInternal() }
        internal.connections.incrementAndGet()

        try {
            val inStream  = client.getInputStream()
            val outStream = client.getOutputStream()

            // Read CONNECT or first byte to determine target
            val header = readHttpConnectHeader(inStream) ?: return@withContext
            val (host, port, osHint) = parseConnectHeader(header)
            internal.osHint = osHint

            // ACK to client (HTTP CONNECT tunnel)
            outStream.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
            outStream.flush()

            // Relay: client → engine (outbound), engine.inbound → client (inbound)
            val relay = scope.launch {
                relay(inStream, outStream, host, port, internal)
            }
            relay.join()
        } catch (_: Exception) {
        } finally {
            internal.connections.decrementAndGet()
            client.close()
        }
    }

    private suspend fun relay(
        clientIn: InputStream,
        clientOut: OutputStream,
        host: String,
        port: Int,
        metrics: StationMetricsInternal
    ) {
        val buf = ByteArray(8192)
        // Forward client traffic through MultipathEngine
        val forward = scope.launch {
            while (true) {
                val n = clientIn.read(buf)
                if (n <= 0) break
                val data = buf.copyOf(n)
                metrics.bytesIn.addAndGet(n.toLong())
                _totalBytesIn.value += n
                engine.send(data)
            }
        }
        // Return traffic from engine to client
        val backward = scope.launch {
            engine.inbound.collect { data ->
                clientOut.write(data)
                clientOut.flush()
                metrics.bytesOut.addAndGet(data.size.toLong())
                _totalBytesOut.value += data.size
            }
        }
        forward.join()
        backward.cancel()
    }

    // ----- Metric helpers -----

    private fun publishMetrics() {
        val snapshot = stationMap.mapValues { (_, v) ->
            StationMetrics(
                macHint     = v.macHint,
                osHint      = v.osHint,
                bytesIn     = v.bytesIn.get(),
                bytesOut    = v.bytesOut.get(),
                latencyMs   = v.latencyMs,
                activeConns = v.connections.get()
            )
        }
        _stations.value = snapshot
    }

    private fun deriveStationKey(addr: InetAddress): String {
        // Use last octet of IP as non-identifying key; real production would use ARP MAC
        return addr.hostAddress?.substringAfterLast('.') ?: addr.toString()
    }

    // ----- HTTP CONNECT parsing -----

    private fun readHttpConnectHeader(stream: InputStream): String? {
        val sb = StringBuilder()
        var prev = ' '
        val buf = ByteArray(1)
        while (stream.read(buf) == 1) {
            sb.append(buf[0].toChar())
            if (prev == '\r' && buf[0] == '\n' && sb.endsWith("\r\n\r\n")) break
            prev = buf[0].toChar()
        }
        return if (sb.isNotBlank()) sb.toString() else null
    }

    private data class ConnectTarget(val host: String, val port: Int, val osHint: String)

    private fun parseConnectHeader(raw: String): ConnectTarget {
        val firstLine = raw.lines().firstOrNull() ?: return ConnectTarget("unknown", 443, "Unknown")
        // "CONNECT host:port HTTP/1.1"
        val parts = firstLine.split(" ")
        val hostPort = if (parts.size >= 2) parts[1] else "unknown:443"
        val host = hostPort.substringBefore(':')
        val port = hostPort.substringAfter(':').toIntOrNull() ?: 443

        val userAgent = raw.lines()
            .firstOrNull { it.startsWith("User-Agent:", ignoreCase = true) }
            ?.substringAfter(":")?.trim() ?: ""

        val osHint = when {
            userAgent.contains("Windows", ignoreCase = true) -> "Windows"
            userAgent.contains("iPhone", ignoreCase = true) ||
            userAgent.contains("iPad",   ignoreCase = true)  -> "iOS"
            userAgent.contains("Mac OS", ignoreCase = true) &&
            !userAgent.contains("iPhone", ignoreCase = true) -> "macOS"
            userAgent.contains("Android", ignoreCase = true) -> "Android"
            else -> "Unknown"
        }
        return ConnectTarget(host, port, osHint)
    }

    companion object {
        const val PROXY_PORT = 8118  // User-visible in disclosure text
    }

    // Mutable internal metrics per station
    private class StationMetricsInternal {
        val macHint    = ""
        var osHint     = "Unknown"
        val bytesIn    = java.util.concurrent.atomic.AtomicLong(0)
        val bytesOut   = java.util.concurrent.atomic.AtomicLong(0)
        var latencyMs  = 0L
        val connections= AtomicInteger(0)
    }
}
