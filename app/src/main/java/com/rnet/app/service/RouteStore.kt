package com.rnet.app.service

import android.content.Context
import android.util.Log
import org.json.JSONObject
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

    fun load(context: Context) {
        if (loaded) return
        loaded = true
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val now = System.currentTimeMillis()
            var count = 0
            for ((key, value) in prefs.all) {
                try {
                    val j = JSONObject(value as String)
                    val savedAt = j.getLong("at")
                    if (now - savedAt < TTL_MS) {
                        store[key] = PersistedRoute(
                            region = j.getString("region"),
                            port   = j.optInt("port", 0),
                            savedAtMs = savedAt,
                            hitCount  = j.optInt("hits", 0)
                        )
                        count++
                    }
                } catch (_: Exception) {}
            }
            Log.i(TAG, "Loaded $count route entries from disk")
        } catch (e: Exception) {
            Log.w(TAG, "RouteStore load failed: ${e.message}")
        }
    }

    fun save(context: Context) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val ed = prefs.edit()
            val now = System.currentTimeMillis()
            ed.clear()
            for ((key, r) in store) {
                if (now - r.savedAtMs < TTL_MS) {
                    ed.putString(key, JSONObject().apply {
                        put("region", r.region)
                        put("port",   r.port)
                        put("at",     r.savedAtMs)
                        put("hits",   r.hitCount)
                    }.toString())
                }
            }
            ed.apply()
            Log.d(TAG, "Saved ${store.size} route entries")
        } catch (e: Exception) {
            Log.w(TAG, "RouteStore save failed: ${e.message}")
        }
    }

    fun get(key: String): PersistedRoute? {
        val r = store[key] ?: return null
        if (System.currentTimeMillis() - r.savedAtMs > TTL_MS) {
            store.remove(key); return null
        }
        r.hitCount++
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
