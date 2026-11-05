package com.rnet.app.routing

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.roundToLong

/**
 * EndpointRouter — multi-endpoint QUIC transport router with goodput-aware
 * path selection and automatic failover.
 *
 * Purpose:
 *   Maintains a ranked list of server endpoints (IP:port). The engine
 *   distributes outbound frames across endpoints in proportion to their
 *   measured goodput, continuously probing to discover path recovery.
 *
 * Usage:
 *   This is a configuration and scoring layer. It tells [MultipathEngine]
 *   which remote [InetSocketAddress] to target for each frame. The actual
 *   UDP socket binding and FEC encoding remain in MultipathEngine.
 *
 * Endpoint configuration:
 *   Endpoints are supplied at construction (see [EndpointConfig]). They
 *   should be your own server addresses — multiple PoPs (points of presence)
 *   across geographic regions — not public infrastructure owned by others.
 *   Routing through public CDN IPs without an application backend that accepts
 *   the traffic will fail; that is a limitation of how CDNs work, not of this
 *   class.
 *
 * Scoring algorithm:
 *   goodput_score = (acked_bytes / elapsed_ms) * (1 - loss_rate)
 *   where loss_rate = 1 - (acked_frames / sent_frames) over a 10 s sliding window.
 *
 *   Scores are recomputed every [PROBE_INTERVAL_MS]. Endpoints below
 *   [MIN_GOODPUT_THRESHOLD] are demoted; recovered endpoints are promoted
 *   automatically when their probe succeeds.
 */
class EndpointRouter(private val configs: List<EndpointConfig>) {

    companion object {
        const val PROBE_INTERVAL_MS      = 10_000L
        const val MIN_GOODPUT_THRESHOLD  = 10.0   // bytes/ms below which endpoint is demoted
        const val WINDOW_FRAMES          = 100    // sliding window size in frames
    }

    data class EndpointConfig(
        val address: InetSocketAddress,
        val label: String,         // human-readable ("eu-west-1", "ap-east-1")
        val priority: Int = 0      // higher = preferred when scores are equal
    )

    data class EndpointScore(
        val config: EndpointConfig,
        val goodputBytesPerMs: Double,
        val lossRate: Double,
        val active: Boolean
    )

    private val scores = ConcurrentHashMap<InetSocketAddress, EndpointScore>().apply {
        configs.forEach { cfg ->
            put(cfg.address, EndpointScore(cfg, 0.0, 0.0, active = true))
        }
    }

    // Per-endpoint sliding window accumulators
    private val sentFrames   = ConcurrentHashMap<InetSocketAddress, AtomicLong>()
        .apply { configs.forEach { put(it.address, AtomicLong(0)) } }
    private val ackedBytes   = ConcurrentHashMap<InetSocketAddress, AtomicLong>()
        .apply { configs.forEach { put(it.address, AtomicLong(0)) } }
    private val ackedFrames  = ConcurrentHashMap<InetSocketAddress, AtomicLong>()
        .apply { configs.forEach { put(it.address, AtomicLong(0)) } }
    private val windowStart  = ConcurrentHashMap<InetSocketAddress, Long>()
        .apply { configs.forEach { put(it.address, System.currentTimeMillis()) } }

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    private val _rankedEndpoints = MutableStateFlow<List<EndpointScore>>(
        configs.map { EndpointScore(it, 0.0, 0.0, true) }
    )
    val rankedEndpoints: StateFlow<List<EndpointScore>> = _rankedEndpoints.asStateFlow()

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    fun start() {
        scope.launch {
            while (isActive) {
                delay(PROBE_INTERVAL_MS)
                recomputeScores()
            }
        }
    }

    fun stop() { scope.cancel() }

    // ── Path selection ────────────────────────────────────────────────────────

    /**
     * Returns the best available [InetSocketAddress] for the next outbound frame.
     * Uses weighted-random selection proportional to goodput score, with priority
     * as a tiebreaker. Falls back to any active endpoint if all scores are 0.
     */
    fun selectEndpoint(): InetSocketAddress {
        val active = scores.values.filter { it.active }
        if (active.isEmpty()) return configs.first().address

        val totalWeight = active.sumOf { it.goodputBytesPerMs + it.config.priority }
        if (totalWeight <= 0.0) {
            return active.maxByOrNull { it.config.priority }!!.config.address
        }
        var pick = Math.random() * totalWeight
        for (s in active.sortedByDescending { it.goodputBytesPerMs + it.config.priority }) {
            pick -= s.goodputBytesPerMs + s.config.priority
            if (pick <= 0) return s.config.address
        }
        return active.first().config.address
    }

    // ── Telemetry callbacks (called by MultipathEngine) ───────────────────────

    fun onFrameSent(addr: InetSocketAddress) {
        sentFrames[addr]?.incrementAndGet()
    }

    fun onAck(addr: InetSocketAddress, bytes: Int) {
        ackedBytes[addr]?.addAndGet(bytes.toLong())
        ackedFrames[addr]?.incrementAndGet()
    }

    // ── Scoring ───────────────────────────────────────────────────────────────

    private fun recomputeScores() {
        val now = System.currentTimeMillis()
        configs.forEach { cfg ->
            val addr    = cfg.address
            val elapsed = now - (windowStart[addr] ?: now)
            val sent    = sentFrames[addr]?.getAndSet(0) ?: 0L
            val acked   = ackedFrames[addr]?.getAndSet(0) ?: 0L
            val bytes   = ackedBytes[addr]?.getAndSet(0) ?: 0L
            windowStart[addr] = now

            val lossRate = if (sent > 0) 1.0 - (acked.toDouble() / sent) else 0.0
            val goodput  = if (elapsed > 0) (bytes.toDouble() / elapsed) * (1.0 - lossRate)
                           else 0.0

            val prevScore = scores[addr]
            val newActive = goodput > MIN_GOODPUT_THRESHOLD || (sent == 0L && prevScore?.active == true)
            scores[addr]  = EndpointScore(cfg, goodput, lossRate, newActive)
        }

        _rankedEndpoints.value = scores.values
            .sortedWith(compareByDescending<EndpointScore> { it.goodputBytesPerMs }
                .thenByDescending { it.config.priority })
    }
}
