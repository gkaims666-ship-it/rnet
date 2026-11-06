package com.rnet.app.service

import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * SmartRouter — per-destination exit-country selector.
 *
 * For each destination IP/port pair, finds the best proxy automatically:
 *   1. Check cache: if we've seen this IP before, reuse the working proxy
 *   2. Try the user's preferred region first (fastest path, usually works)
 *   3. On failure: probe the fallback order until one works
 *   4. Cache the winner for future connections to the same IP
 *   5. If all proxies fail: try direct connection as last resort
 *
 * Cache entries expire after CACHE_TTL_MS (1 hour) so we re-probe if
 * something that was blocked becomes unblocked, or vice versa.
 *
 * Concurrency: each probe is a blocking SOCKS5 test on a pool thread.
 * Multiple simultaneous probes for the same IP are coalesced — only
 * one test runs, others wait for the result.
 */
class SmartRouter(
    private val pool: TunnelPool,
    private val preferredRegion: String,
    private val vpnService: android.net.VpnService
) {
    companion object {
        private const val TAG = "SmartRouter"
        private const val CACHE_TTL_MS  = 60 * 60 * 1000L   // 1 hour
        private const val PROBE_TIMEOUT = 6_000              // ms per probe
        private const val SOCK_BUF      = 262144

        // Probe order: preferred first, then fallback chain, then direct
        // "DIRECT" is a sentinel meaning no proxy
        const val DIRECT = "DIRECT"

        // Regions to try in order when preferred fails
        private val FALLBACK_ORDER = listOf("IS", "EE", "DE", "NL", "SE", "CH", "US", "CA", "GB")
    }

    data class RouteEntry(
        val proxy: String,     // region code, or DIRECT
        val port: Int,         // SOCKS5 port (0 if DIRECT)
        val cachedAtMs: Long = System.currentTimeMillis()
    )

    // key = "dstIP:dstPort"
    private val cache = ConcurrentHashMap<String, RouteEntry>()

    // Per-destination lock to coalesce concurrent probes
    private val probeLocks = ConcurrentHashMap<String, Object>()

    // Public stats for UI
    @Volatile var routeCacheSize: Int = 0
    @Volatile var lastRoutedRegion: String = preferredRegion

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Get the best connected socket for dstIP:dstPort.
     * Blocks until connection is established or all options exhausted.
     * Returns null only if everything failed.
     */
    fun connect(dstIP: InetAddress, dstPort: Int): Socket? {
        val key = "${dstIP.hostAddress}:$dstPort"

        // Check cache first (fast path)
        val cached = cache[key]
        if (cached != null && !isExpired(cached)) {
            val sock = tryConnect(dstIP, dstPort, cached.proxy, cached.port)
            if (sock != null) {
                lastRoutedRegion = cached.proxy
                return sock
            }
            // Cached route failed — evict and re-probe
            cache.remove(key)
        }

        // Coalesce concurrent probes for same destination
        val lock = probeLocks.getOrPut(key) { Object() }
        synchronized(lock) {
            // Another thread may have populated cache while we waited
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

    /** Force-evict a cache entry (call when a session dies mid-stream). */
    fun invalidate(dstIP: InetAddress, dstPort: Int) {
        cache.remove("${dstIP.hostAddress}:$dstPort")
    }

    /** Clear expired entries. Call every few minutes. */
    fun evictExpired() {
        cache.entries.removeIf { isExpired(it.value) }
        routeCacheSize = cache.size
    }

    // ── Probe logic ───────────────────────────────────────────────────────────

    private fun probe(dstIP: InetAddress, dstPort: Int, key: String): Socket? {
        // Build probe order: preferred first, then fallbacks (deduplicated), then DIRECT
        val order = buildList {
            add(preferredRegion)
            FALLBACK_ORDER.forEach { if (it != preferredRegion) add(it) }
            add(DIRECT)
        }

        for (region in order) {
            if (!pool.alive) return null

            val (proxy, port) = if (region == DIRECT) {
                Pair(DIRECT, 0)
            } else {
                val p = pool.getSocksPort(region)
                if (p <= 0) continue   // tunnel failed to start for this region
                Pair(region, p)
            }

            Log.d(TAG, "Probing $key via $region")
            val sock = tryConnect(dstIP, dstPort, proxy, port)
            if (sock != null) {
                val entry = RouteEntry(proxy, port)
                cache[key] = entry
                routeCacheSize = cache.size
                lastRoutedRegion = proxy
                Log.i(TAG, "✓ $key → $region")
                return sock
            }
            Log.d(TAG, "✗ $key via $region")
        }

        Log.w(TAG, "All routes failed for $key")
        return null
    }

    private fun tryConnect(dstIP: InetAddress, dstPort: Int, proxy: String, proxyPort: Int): Socket? {
        return try {
            if (proxy == DIRECT) {
                connectDirect(dstIP, dstPort)
            } else {
                connectSocks5(dstIP, dstPort, "127.0.0.1", proxyPort)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun connectDirect(dstIP: InetAddress, dstPort: Int): Socket {
        val s = Socket(); vpnService.protect(s)
        s.setReceiveBufferSize(SOCK_BUF); s.setSendBufferSize(SOCK_BUF)
        s.tcpNoDelay = true
        s.connect(InetSocketAddress(dstIP, dstPort), PROBE_TIMEOUT)
        return s
    }

    private fun connectSocks5(dstIP: InetAddress, dstPort: Int,
                               proxyHost: String, proxyPort: Int): Socket {
        val s = Socket(); vpnService.protect(s)
        s.setReceiveBufferSize(SOCK_BUF); s.setSendBufferSize(SOCK_BUF)
        s.tcpNoDelay = true
        s.soTimeout = PROBE_TIMEOUT
        s.connect(InetSocketAddress(proxyHost, proxyPort), PROBE_TIMEOUT)

        val sin = s.getInputStream(); val sout = s.getOutputStream()
        // SOCKS5 greeting
        sout.write(byteArrayOf(0x05, 0x01, 0x00)); sout.flush()
        val gr = ByteArray(2); sin.readFully(gr)
        if (gr[0] != 0x05.toByte() || gr[1] != 0x00.toByte())
            throw java.io.IOException("SOCKS5 auth rejected")
        // CONNECT with IPv4 (ATYP=1)
        val ip = dstIP.address
        val req = ByteArray(10)
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01
        ip.copyInto(req, 4)
        req[8] = (dstPort shr 8).toByte(); req[9] = (dstPort and 0xFF).toByte()
        sout.write(req); sout.flush()
        // Response
        val resp = ByteArray(10); sin.readFully(resp)
        if (resp[0] != 0x05.toByte() || resp[1] != 0x00.toByte())
            throw java.io.IOException("SOCKS5 CONNECT rejected: ${resp[1]}")
        s.soTimeout = 0  // remove timeout for data phase
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
