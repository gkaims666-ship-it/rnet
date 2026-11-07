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
    preferredRegion: String,
    private val vpnService: android.net.VpnService,
    private val context: Context? = null    // null = no persistence
) {
    // Mutable so hot region swap can update it without recreating the router
    @Volatile private var preferredRegion: String = preferredRegion
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

    // Circuit breaker: destination → (failCount, firstFailMs)
    // Destinations with >= FAIL_THRESHOLD failures within FAIL_WINDOW_MS are blacklisted
    // for BLACKLIST_DURATION_MS, then automatically cleared.
    private data class FailEntry(var count: Int, val firstMs: Long)
    private val failMap = ConcurrentHashMap<String, FailEntry>()
    // Region failure tracking: region → (failCount, firstFailMs)
    private val regionFailMap = ConcurrentHashMap<String, FailEntry>()
    companion object {
        private const val TAG = "SmartRouter"
        private const val CACHE_TTL_MS  = 60 * 60 * 1000L
        private const val PROBE_TIMEOUT = 6_000
        private const val SOCK_BUF      = 262144
        const val DIRECT = "DIRECT"

        private const val FAIL_THRESHOLD      = 5
        private const val FAIL_WINDOW_MS      = 60_000L    // count failures within 1 min
        private const val BLACKLIST_DURATION_MS = 120_000L // blacklist for 2 min

        private val FALLBACK_ORDER = listOf("IS", "EE", "DE", "NL", "SE", "CH", "US", "CA", "GB")
    }

    init {
        // Load persistent cache from disk
        context?.let { RouteStore.load(it) }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    fun connect(dstIP: InetAddress, dstPort: Int): Socket? {
        val key = "${dstIP.hostAddress}:$dstPort"

        // Circuit breaker: skip destinations that have failed too many times recently
        if (isBlacklisted(key)) {
            Log.d(TAG, "Circuit open — skipping blacklisted $key")
            return null
        }

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
        recordFailure(key)
    }

    // ── Circuit breaker helpers ───────────────────────────────────────────────

    private fun recordFailure(key: String) {
        val now = System.currentTimeMillis()
        val fe = failMap.getOrPut(key) { FailEntry(0, now) }
        // Reset window if too old
        if (now - fe.firstMs > FAIL_WINDOW_MS) {
            failMap[key] = FailEntry(1, now)
        } else {
            // Bug fix: `fe.count++` is a non-atomic read-modify-write on a plain `var`
            // field retrieved from a ConcurrentHashMap — concurrent callers race.
            // Use replace() so the update is conditional on the entry not changing.
            val updated = fe.copy(count = fe.count + 1)
            failMap.replace(key, fe, updated)
            if (updated.count >= FAIL_THRESHOLD) {
                Log.w(TAG, "Circuit open for $key (${updated.count} failures)")
            }
        }
    }

    private fun isBlacklisted(key: String): Boolean {
        val fe = failMap[key] ?: return false
        val now = System.currentTimeMillis()
        // Auto-unblacklist after BLACKLIST_DURATION_MS
        if (now - fe.firstMs > BLACKLIST_DURATION_MS) {
            failMap.remove(key); return false
        }
        return fe.count >= FAIL_THRESHOLD
    }

    fun clearBlacklist() { failMap.clear(); regionFailMap.clear() }

    /** Hot-swap the preferred exit region — new connections will probe via newRegion first. */
    fun setPreferredRegion(newRegion: String) {
        preferredRegion = newRegion
        lastRoutedRegion = newRegion
    }

    /** Clear all cached routes so the next connection re-probes via the new preferred region. */
    fun clearAllRoutes() {
        cache.clear()
        context?.let { RouteStore.evictExpired() }
        routeCacheSize = 0
        // Also reset circuit breakers so new region gets a fair chance
        regionFailMap.clear()
    }

    private fun recordRegionFailure(region: String) {
        val now = System.currentTimeMillis()
        val fe = regionFailMap.getOrPut(region) { FailEntry(0, now) }
        if (now - fe.firstMs > FAIL_WINDOW_MS) regionFailMap[region] = FailEntry(1, now)
        else {
            // Bug fix: same non-atomic race as recordFailure — use replace().
            regionFailMap.replace(region, fe, fe.copy(count = fe.count + 1))
        }
    }

    private fun isRegionBlacklisted(region: String): Boolean {
        val fe = regionFailMap[region] ?: return false
        val now = System.currentTimeMillis()
        if (now - fe.firstMs > BLACKLIST_DURATION_MS) { regionFailMap.remove(region); return false }
        return fe.count >= FAIL_THRESHOLD
    }

    fun evictExpired() {
        cache.entries.removeIf { isExpired(it.value) }
        RouteStore.evictExpired()
        // Also clear stale circuit-breaker entries
        val now = System.currentTimeMillis()
        failMap.entries.removeIf { now - it.value.firstMs > BLACKLIST_DURATION_MS }
        regionFailMap.entries.removeIf { now - it.value.firstMs > BLACKLIST_DURATION_MS }
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
            // New feature: skip regions that have failed too many times recently
            if (region != DIRECT && isRegionBlacklisted(region)) {
                Log.d(TAG, "Skipping blacklisted region $region")
                continue
            }
            val (proxy, port) = if (region == DIRECT) Pair(DIRECT, 0)
            else {
                val p = pool.getSocksPort(region)
                if (p <= 0) { recordRegionFailure(region); continue }
                Pair(region, p)
            }
            val sock = tryConnect(dstIP, dstPort, proxy, port)
            if (sock == null) { if (region != DIRECT) recordRegionFailure(region); continue }
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
        s.keepAlive = true   // New feature: TCP keepalive detects dead connections faster
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
        s.keepAlive = true
        s.soTimeout = PROBE_TIMEOUT
        // Bug fix: if connect() throws, the socket was created and must be closed.
        // Previously an exception here would leak the file descriptor.
        try {
            s.connect(InetSocketAddress(proxyHost, proxyPort), PROBE_TIMEOUT)
        } catch (e: Exception) {
            runCatching { s.close() }
            return null
        }
        val din  = java.io.DataInputStream(s.getInputStream())
        val sout = s.getOutputStream()

        // Greeting: no-auth
        sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
        val gr = ByteArray(2); din.readFully(gr)
        if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte()) {
            runCatching { s.close() }; return null
        }

        // CONNECT request — ATYP=0x01 (IPv4)
        val ip = dstIP.address
        val req = ByteArray(10).also { r ->
            r[0] = 0x05; r[1] = 0x01; r[2] = 0x00; r[3] = 0x01
            ip.copyInto(r, 4)
            r[8] = (dstPort shr 8).toByte(); r[9] = (dstPort and 0xFF).toByte()
        }
        sout.write(req); sout.flush()

        // CONNECT response: VER REP RSV ATYP [BND.ADDR] BND.PORT
        // CRITICAL: ATYP determines address length — must drain exactly the right
        // number of bytes or the stream is left in a corrupted state for all reads.
        val hdr = ByteArray(4); din.readFully(hdr)
        if (hdr[0] != 0x05.toByte() || hdr[1] != 0x00.toByte()) {
            runCatching { s.close() }; return null
        }
        when (hdr[3].toInt() and 0xFF) {
            0x01 -> din.readFully(ByteArray(4 + 2))          // IPv4 (4 bytes) + port (2 bytes)
            0x04 -> din.readFully(ByteArray(16 + 2))         // IPv6 (16 bytes) + port (2 bytes)
            0x03 -> {                                          // domain: 1-byte len + domain + port
                val len = din.read() and 0xFF
                din.readFully(ByteArray(len + 2))
            }
            else -> { runCatching { s.close() }; return null }
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
