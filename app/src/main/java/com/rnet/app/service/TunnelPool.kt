package com.rnet.app.service

import android.content.Context
import android.util.Log
import com.rnet.app.transport.PsiphonTransport
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * TunnelPool — manages up to MAX_TUNNELS Psiphon tunnels in parallel.
 *
 * Each tunnel exits in a different country. SmartRouter asks this pool for the
 * SOCKS5 port for a given region; the pool spins up the tunnel on first request
 * and shuts it down after IDLE_TIMEOUT_MS of non-use.
 *
 * Max simultaneous tunnels = 4 (keeps RAM under ~200 MB total).
 * When all slots are full, the least-recently-used tunnel is replaced.
 */
class TunnelPool(
    private val context: Context,
    private val onProtect: (java.net.Socket) -> Boolean
) {
    companion object {
        private const val TAG = "TunnelPool"
        const val MAX_TUNNELS = 4
        private const val IDLE_TIMEOUT_MS = 5 * 60 * 1000L   // 5 min
        private const val START_TIMEOUT_MS = 60_000L
    }

    data class TunnelEntry(
        val region: String,
        val transport: PsiphonTransport,
        @Volatile var port: Int = 0,
        @Volatile var ready: Boolean = false,
        @Volatile var lastUsedMs: Long = System.currentTimeMillis(),
        // Bug fix #5: latch lets other threads wait for startup without holding the lock
        val startLatch: CountDownLatch = CountDownLatch(1)
    )

    private val tunnels = ConcurrentHashMap<String, TunnelEntry>()
    private val lock    = ReentrantLock()
    private val startPool = Executors.newCachedThreadPool()

    @Volatile var alive = true

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Get the SOCKS5 port for the given region.
     * Starts the tunnel if not running. Returns -1 on failure.
     * Bug fix #5: if a startup is already in progress, wait on its latch instead of
     * competing for the lock (avoids one 60s startup blocking all others).
     */
    fun getSocksPort(region: String): Int {
        val entry = tunnels[region]
        if (entry != null) {
            if (entry.ready) {
                entry.lastUsedMs = System.currentTimeMillis()
                return entry.port
            }
            // Startup already in progress — wait for it rather than blocking the lock
            if (entry.startLatch.await(START_TIMEOUT_MS, TimeUnit.MILLISECONDS) && entry.ready) {
                entry.lastUsedMs = System.currentTimeMillis()
                return entry.port
            }
            return -1
        }
        return startTunnel(region)
    }

    /** Warm-start the default region tunnel in the background immediately. */
    fun warmup(region: String) {
        if (tunnels.containsKey(region)) return
        startPool.execute { startTunnel(region) }
    }

    fun stopAll() {
        alive = false
        tunnels.values.forEach { runCatching { it.transport.stop() } }
        tunnels.clear()
        startPool.shutdownNow()
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private fun startTunnel(region: String): Int {
        val entry: TunnelEntry? = lock.withLock {
            // Double-check after acquiring lock — if already started/starting, don't start again
            tunnels[region]?.let { existing ->
                if (existing.ready) return existing.port   // already ready
                // Startup in progress — release lock and wait on the latch
                // (can't return from inside withLock with a suspend, so null means "wait outside")
                return@withLock null
            }
            // Evict LRU tunnel if at capacity
            if (tunnels.size >= MAX_TUNNELS) evictLru()

            Log.i(TAG, "Starting tunnel for region=$region")
            val transport = PsiphonTransport(context, region)
            val e = TunnelEntry(region, transport)
            tunnels[region] = e
            e   // return the entry; lock is released immediately after
        }

        // If another startup was already in progress, entry is null — wait on its latch
        if (entry == null) {
            val existing = tunnels[region] ?: return -1
            if (existing.startLatch.await(START_TIMEOUT_MS, TimeUnit.MILLISECONDS) && existing.ready) {
                existing.lastUsedMs = System.currentTimeMillis()
                return existing.port
            }
            return -1
        }

        // transport.start() (up to 60s) runs OUTSIDE the lock
        return try {
            val addr = entry.transport.start()
            val port = addr.substringAfterLast(":").toIntOrNull() ?: -1
            if (port > 0) {
                entry.port  = port
                entry.ready = true
                entry.lastUsedMs = System.currentTimeMillis()
                Log.i(TAG, "Tunnel $region ready on port $port")
            } else {
                tunnels.remove(region)
                Log.w(TAG, "Tunnel $region returned invalid port")
            }
            port.also { entry.startLatch.countDown() }
        } catch (e: Exception) {
            Log.w(TAG, "Tunnel $region failed: ${e.message}")
            tunnels.remove(region)
            entry.startLatch.countDown()
            -1
        }
    }

    private fun evictLru() {
        val lru = tunnels.values.minByOrNull { it.lastUsedMs } ?: return
        Log.i(TAG, "Evicting LRU tunnel: ${lru.region}")
        runCatching { lru.transport.stop() }
        tunnels.remove(lru.region)
    }

    /** Stop tunnels idle for longer than IDLE_TIMEOUT_MS. Call periodically. */
    fun evictIdle() {
        val cutoff = System.currentTimeMillis() - IDLE_TIMEOUT_MS
        tunnels.entries.removeIf { (region, entry) ->
            if (entry.lastUsedMs < cutoff) {
                Log.i(TAG, "Evicting idle tunnel: $region")
                runCatching { entry.transport.stop() }
                true
            } else false
        }
    }

    /** True if region has a ready tunnel. */
    fun isReady(region: String) = tunnels[region]?.ready == true

    /** All currently active region codes. */
    fun activeRegions(): List<String> = tunnels.keys.toList()
}
