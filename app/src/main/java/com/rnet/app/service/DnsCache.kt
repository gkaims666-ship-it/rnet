package com.rnet.app.service

import android.content.Context
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * DnsCache — persistent DNS resolution cache with TTL.
 *
 * Stores hostname → IP mappings in SharedPreferences so they survive VPN restarts.
 * Saves ~100–200ms per connection to frequently visited domains by skipping DoH.
 *
 * TTL = 5 minutes (DNS standard minimum). Expired entries are re-resolved.
 * Max 500 entries — LRU eviction when full.
 */
object DnsCache {
    private const val TAG = "DnsCache"
    private const val PREFS_NAME = "rnet_dns_cache"
    private const val TTL_MS = 5 * 60 * 1000L   // 5 minutes
    private const val MAX_ENTRIES = 500

    data class Entry(
        val ip: String,
        val cachedAtMs: Long = System.currentTimeMillis(),
        var lastUsedMs: Long = System.currentTimeMillis()
    )

    private val mem = ConcurrentHashMap<String, Entry>(256)
    @Volatile private var loaded = false

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Zero-retention: resolved hostnames live ONLY in memory for the current
     * session. The list of domains you look up is never written to disk.
     *
     * load() no longer reads from disk; it wipes any DNS history an older build
     * may have persisted, so upgrading also cleans up the on-disk trail.
     */
    fun load(context: Context) {
        if (loaded) return
        loaded = true
        try {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().clear().apply()
        } catch (_: Exception) {}
    }

    /** No-op by design: resolved hostnames are never written to disk (zero-retention). */
    fun save(context: Context) {
        // Intentionally empty — see load() / class docs.
    }

    /**
     * Look up a hostname. Returns cached InetAddress if fresh, null if expired/missing.
     */
    fun get(host: String): InetAddress? {
        val entry = mem[host] ?: return null
        if (System.currentTimeMillis() - entry.cachedAtMs > TTL_MS) {
            mem.remove(host)
            return null
        }
        entry.lastUsedMs = System.currentTimeMillis()
        return try { InetAddress.getByName(entry.ip) } catch (_: Exception) { null }
    }

    /**
     * Store a resolved hostname → IP mapping.
     */
    fun put(host: String, addr: InetAddress) {
        if (mem.size >= MAX_ENTRIES) evictLru()
        mem[host] = Entry(addr.hostAddress ?: return)
    }

    /** Clear expired entries. */
    fun evictExpired() {
        val now = System.currentTimeMillis()
        mem.entries.removeIf { now - it.value.cachedAtMs > TTL_MS }
    }

    fun size() = mem.size

    // ── Internal ──────────────────────────────────────────────────────────────

    private fun evictLru() {
        // Remove oldest 20% when full
        val toRemove = (MAX_ENTRIES * 0.2).toInt().coerceAtLeast(1)
        mem.entries
            .sortedBy { it.value.lastUsedMs }
            .take(toRemove)
            .forEach { mem.remove(it.key) }
    }
}
