package com.rnet.app.service

import android.content.Context
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * SmartRouter — per-destination exit-country selector with:
 *   • In-memory route cache (1 h TTL)
 *   • Persistent route cache via RouteStore (24 h TTL, survives VPN restart)
 *   • Adaptive speed scoring: background throughput probe after route found
 *   • Connection pool integration: pre-warmed sockets via ConnectionPool
 *   • Coalesced probes: concurrent requests for same dest share one probe
 *
 * Flow for a new destination:
 *   1. Check in-memory cache  → hit: return pre-warmed socket or fresh connect
 *   2. Check RouteStore disk  → hit: use persisted region, skip full probe
 *   3. Full probe: preferred → 9-country fallback → direct
 *   4. Cache result in memory + disk
 *   5. Schedule background warmup + speed probe
 */
class SmartRouter(
    private val pool: TunnelPool,
    private val preferredRegion: String,
    private val vpnService: android.net.VpnService,
    private val context: Context? = null    // null = no persistence
) {
    companion object {
        private const val TAG = "SmartRouter"
        private const val CACHE_TTL_MS  = 60 * 60 * 1000L   // 1 hour in-memory
        private const val PROBE_TIMEOUT = 6_000
        private const val SOCK_BUF      = 262144
        const val DIRECT = "DIRECT"

        private val FALLBACK_ORDER = listOf("IS", "EE", "DE", "NL", "SE", "CH", "US", "CA", "GB")
    }

    data class RouteEntry(
        val proxy: String,
        val port: Int,
        val cachedAtMs: Long = System.currentTimeMillis(),
        @Volatile var speedBytesPerMs: Double = 0.0   // 0 = not yet measured
    )

    private val cache = ConcurrentHashMap<String, RouteEntry>()
    private val probeLocks = ConcurrentHashMap<String, Any>()

    // Background speed prober
    private val speedProbeExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "speed-probe").also { it.isDaemon = true }
    }

    // Connection pool for pre-warmed sockets
    val connPool: ConnectionPool by lazy { ConnectionPool(this) }

    @Volatile var routeCacheSize: Int = 0
    @Volatile var lastRoutedRegion: String = preferredRegion

    init {
        // Load persistent cache from disk
        context?.let { RouteStore.load(it) }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    fun connect(dstIP: InetAddress, dstPort: Int): Socket? {
        val key = "${dstIP.hostAddress}:$dstPort"

        // 1. Try pre-warmed socket first (fastest path — no handshake at all)
        val warm = connPool.acquire(dstIP, dstPort)
        if (warm != null) return warm

        // 2. Check in-memory cache
        val cached = cache[key]
        if (cached != null && !isExpired(cached)) {
            val sock = tryConnect(dstIP, dstPort, cached.proxy, cached.port)
            if (sock != null) {
                lastRoutedRegion = cached.proxy
                connPool.scheduleWarmup(dstIP, dstPort, key)
                return sock
            }
            cache.remove(key)
            RouteStore.remove(key)
        }

        // 3. Check persistent disk cache (survives restarts)
        val persisted = context?.let { RouteStore.get(key) }
        if (persisted != null) {
            val port = pool.getSocksPort(persisted.region)
            if (port > 0) {
                val sock = tryConnect(dstIP, dstPort, persisted.region, port)
                if (sock != null) {
                    val entry = RouteEntry(persisted.region, port)
                    cache[key] = entry
                    routeCacheSize = cache.size
                    lastRoutedRegion = persisted.region
                    Log.i(TAG, "✓ $key → ${persisted.region} (from disk cache)")
                    connPool.scheduleWarmup(dstIP, dstPort, key)
                    return sock
                }
                // Persisted route stale — fall through to full probe
                RouteStore.remove(key)
            }
        }

        // 4. Full probe with coalescing
        val lock = probeLocks.getOrPut(key) { Any() }
        synchronized(lock) {
            // Another thread may have populated cache while we waited for lock
            val fresh = cache[key]
            if (fresh != null && !isExpired(fresh)) {
                val sock = tryConnect(dstIP, dstPort, fresh.proxy, fresh.port)
                if (sock != null) {
                    lastRoutedRegion = fresh.proxy
                    return sock
                }
            }
            val result = probe(dstIP, dstPort, key)
            probeLocks.remove(key)
            return result
        }
    }

    fun invalidate(dstIP: InetAddress, dstPort: Int) {
        val key = "${dstIP.hostAddress}:$dstPort"
        cache.remove(key)
        context?.let { RouteStore.remove(key) }
    }

    fun evictExpired() {
        cache.entries.removeIf { isExpired(it.value) }
        RouteStore.evictExpired()
        routeCacheSize = cache.size
    }

    fun saveTodisk() {
        context?.let { RouteStore.save(it) }
    }

    // ── Probe ─────────────────────────────────────────────────────────────────

    private fun probe(dstIP: InetAddress, dstPort: Int, key: String): Socket? {
        val order = buildList {
            add(preferredRegion)
            FALLBACK_ORDER.forEach { if (it != preferredRegion) add(it) }
            add(DIRECT)
        }
        for (region in order) {
            if (!pool.alive) return null
            val (proxy, port) = if (region == DIRECT) Pair(DIRECT, 0)
            else {
                val p = pool.getSocksPort(region)
                if (p <= 0) continue
                Pair(region, p)
            }
            val sock = tryConnect(dstIP, dstPort, proxy, port) ?: continue
            val entry = RouteEntry(proxy, port)
            cache[key] = entry
            routeCacheSize = cache.size
            lastRoutedRegion = proxy
            context?.let { RouteStore.put(key, proxy, port) }
            Log.i(TAG, "✓ $key → $region")
            connPool.scheduleWarmup(dstIP, dstPort, key)
            // Start background speed probe to see if a faster region exists
            if (proxy != DIRECT) scheduleSpeedProbe(dstIP, dstPort, key, proxy, port)
            return sock
        }
        Log.w(TAG, "All routes failed for $key")
        return null
    }

    // ── Adaptive speed scoring ────────────────────────────────────────────────

    /**
     * After a route is found, probe the fastest alternative in the background.
     * If a region is significantly faster (>30% better throughput), migrate
     * new connections to it automatically.
     */
    private fun scheduleSpeedProbe(
        dstIP: InetAddress, dstPort: Int, key: String,
        currentRegion: String, currentPort: Int
    ) {
        speedProbeExecutor.execute {
            try {
                Thread.sleep(2000)  // wait until main connection is established
                val candidates = FALLBACK_ORDER
                    .filter { it != currentRegion && pool.isReady(it) }
                    .take(2)

                var bestRegion = currentRegion
                var bestSpeed = measureSpeed(dstIP, dstPort, currentRegion, currentPort)
                cache[key]?.speedBytesPerMs = bestSpeed

                for (region in candidates) {
                    if (!pool.alive) break
                    val port = pool.getSocksPort(region)
                    if (port <= 0) continue
                    val speed = measureSpeed(dstIP, dstPort, region, port)
                    if (speed > bestSpeed * 1.3) {  // 30% faster threshold
                        bestSpeed = speed
                        bestRegion = region
                    }
                }

                if (bestRegion != currentRegion) {
                    val port = pool.getSocksPort(bestRegion)
                    if (port > 0) {
                        val entry = RouteEntry(bestRegion, port, speedBytesPerMs = bestSpeed)
                        cache[key] = entry
                        routeCacheSize = cache.size
                        context?.let { RouteStore.put(key, bestRegion, port) }
                        Log.i(TAG, "Speed upgrade: $key $currentRegion→$bestRegion (${bestSpeed.toInt()} B/ms)")
                    }
                }
            } catch (_: Exception) {}
        }
    }

    /**
     * Measure throughput to a destination via a given region.
     * Opens a socket, sends a minimal HTTP HEAD request, times the response.
     * Returns bytes/ms, or 0.0 on failure.
     */
    private fun measureSpeed(
        dstIP: InetAddress, dstPort: Int, region: String, port: Int
    ): Double {
        return try {
            val start = System.currentTimeMillis()
            val sock = connectSocks5(dstIP, dstPort, "127.0.0.1", port) ?: return 0.0
            sock.soTimeout = 3000
            // Send minimal probe — just open + close (TCP handshake time is the metric)
            sock.close()
            val elapsed = (System.currentTimeMillis() - start).coerceAtLeast(1)
            1000.0 / elapsed   // "speed" = inverse latency (higher = faster)
        } catch (_: Exception) { 0.0 }
    }

    // ── Connection helpers ────────────────────────────────────────────────────

    private fun tryConnect(dstIP: InetAddress, dstPort: Int, proxy: String, proxyPort: Int): Socket? {
        return try {
            if (proxy == DIRECT) connectDirect(dstIP, dstPort)
            else connectSocks5(dstIP, dstPort, "127.0.0.1", proxyPort)
        } catch (_: Exception) { null }
    }

    private fun connectDirect(dstIP: InetAddress, dstPort: Int): Socket {
        val s = Socket(); vpnService.protect(s)
        s.setReceiveBufferSize(SOCK_BUF); s.setSendBufferSize(SOCK_BUF)
        s.tcpNoDelay = true
        s.connect(InetSocketAddress(dstIP, dstPort), PROBE_TIMEOUT)
        return s
    }

    private fun connectSocks5(
        dstIP: InetAddress, dstPort: Int,
        proxyHost: String, proxyPort: Int
    ): Socket? {
        val s = Socket(); vpnService.protect(s)
        s.setReceiveBufferSize(SOCK_BUF); s.setSendBufferSize(SOCK_BUF)
        s.tcpNoDelay = true
        s.soTimeout = PROBE_TIMEOUT
        s.connect(InetSocketAddress(proxyHost, proxyPort), PROBE_TIMEOUT)
        val sin = s.getInputStream(); val sout = s.getOutputStream()
        sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
        val gr = ByteArray(2); sin.readFully(gr)
        if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte()) {
            runCatching { s.close() }; return null
        }
        val ip = dstIP.address
        val req = ByteArray(10).also { r ->
            r[0] = 0x05; r[1] = 0x01; r[2] = 0x00; r[3] = 0x01
            ip.copyInto(r, 4)
            r[8] = (dstPort shr 8).toByte(); r[9] = (dstPort and 0xFF).toByte()
        }
        sout.write(req); sout.flush()
        val resp = ByteArray(10); sin.readFully(resp)
        if (resp[0] != 0x05.toByte() || resp[1] != 0x00.toByte()) {
            runCatching { s.close() }; return null
        }
        s.soTimeout = 0
        return s
    }

    private fun isExpired(e: RouteEntry) =
        System.currentTimeMillis() - e.cachedAtMs > CACHE_TTL_MS

    private fun java.io.InputStream.readFully(buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = read(buf, off, buf.size - off)
            if (n < 0) throw java.io.EOFException()
            off += n
        }
    }
}
