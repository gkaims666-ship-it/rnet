package com.rnet.app.service

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * RouteStore — persistent SmartRouter cache.
 *
 * Saves winning exit-region per destination IP:port to disk so the VPN
 * connects instantly on restart without re-probing all regions.
 *
 * Example: if youtube.com:443 → "DE" (Germany) is cached, next VPN start
 * goes straight to the German Psiphon tunnel — no 6s probe delay.
 *
 * TTL = 24 hours. Max 1000 entries, LRU eviction.
 */
object RouteStore {
    private const val TAG = "RouteStore"
    private const val PREFS_NAME = "rnet_route_cache"
    private const val TTL_MS = 24 * 60 * 60 * 1000L  // 24 hours
    private const val MAX_ENTRIES = 1000

    data class PersistedRoute(
        val region: String,
        val port: Int,          // last known SOCKS port (0 = direct)
        val savedAtMs: Long = System.currentTimeMillis(),
        var hitCount: Int = 0
    )

    private val store = ConcurrentHashMap<String, PersistedRoute>(256)
    @Volatile private var loaded = false

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Zero-retention: routes live ONLY in memory for the current session and are
     * gone when the engine stops or the process dies. We do not write which
     * destinations you connected to — or which exit region served them — to disk.
     *
     * load() no longer reads from disk; it wipes any route history that an older
     * build of the app may have left in SharedPreferences, so upgrading cleans up
     * the on-disk trail as well.
     */
    fun load(context: Context) {
        if (loaded) return
        loaded = true
        try {
            // Purge any previously-persisted route history from disk.
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().clear().apply()
        } catch (_: Exception) {}
    }

    /** No-op by design: route history is never written to disk (zero-retention). */
    fun save(context: Context) {
        // Intentionally empty — see load() / class docs.
    }

    fun get(key: String): PersistedRoute? {
        val r = store[key] ?: return null
        if (System.currentTimeMillis() - r.savedAtMs > TTL_MS) {
            store.remove(key); return null
        }
        // Bug fix: hitCount++ on a shared data class field is a non-atomic read-modify-write.
        // Multiple session threads calling get() concurrently lose increments and corrupt LRU.
        // Replace the entry atomically using ConcurrentHashMap.replace so each increment is safe.
        store.replace(key, r, r.copy(hitCount = r.hitCount + 1))
        // Return the original r — caller only needs the region/port, not the updated hitCount.
        return r
    }

    fun put(key: String, region: String, port: Int) {
        if (store.size >= MAX_ENTRIES) evictLru()
        val existing = store[key]
        store[key] = PersistedRoute(region, port,
            hitCount = (existing?.hitCount ?: 0) + 1)
    }

    fun remove(key: String) { store.remove(key) }

    fun evictExpired() {
        val now = System.currentTimeMillis()
        store.entries.removeIf { now - it.value.savedAtMs > TTL_MS }
    }

    fun size() = store.size

    private fun evictLru() {
        store.entries
            .sortedBy { it.value.hitCount }
            .take((MAX_ENTRIES * 0.2).toInt().coerceAtLeast(1))
            .forEach { store.remove(it.key) }
    }
}
