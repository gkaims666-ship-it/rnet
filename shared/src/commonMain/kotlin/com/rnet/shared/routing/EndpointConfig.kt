package com.rnet.shared.routing

/**
 * Platform-agnostic endpoint descriptor for the multi-endpoint router.
 * The router selects endpoints by weighted-random goodput scoring.
 */
data class EndpointConfig(
    val host: String,
    val port: Int,
    val label: String,
    /** Higher = preferred when goodput scores are equal */
    val priority: Int = 0
)

/**
 * Live scoring for one endpoint, updated every 10-second sliding window.
 * goodput = (ackedBytes / elapsedMs) * (1 - lossRate)
 */
data class EndpointScore(
    val config: EndpointConfig,
    val goodputBytesPerMs: Double,
    val lossRate: Double,
    val active: Boolean
)
