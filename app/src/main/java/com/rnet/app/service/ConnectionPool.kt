package com.rnet.app.service

import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * ConnectionPool — pre-warmed TCP socket pool per destination.
 *
 * After SmartRouter caches a winning route for a destination, this pool
 * pre-opens 2 sockets to that destination so the NEXT request picks up
 * an already-connected socket — skipping TCP handshake (~50ms) AND
 * SOCKS5 negotiation (~30ms) = ~80ms faster per new connection.
 *
 * Usage:
 *   val sock = pool.acquire(dstIP, dstPort) ?: router.connect(...)
 *   // use sock ...
 *   // Don't return sockets — they are single-use (HTTP/1.1 keep-alive
 *   // is handled by the app layer, not by us).
 *
 * Sockets idle > IDLE_TIMEOUT_MS are closed and evicted automatically.
 */
class ConnectionPool(
    private val router: SmartRouter,
    private val maxPerDest: Int = 3,            // perf: pre-warm one extra socket per dest
    private val idleTimeoutMs: Long = 45_000L   // perf: hold warm sockets a bit longer (was 30s)
) {
    companion object {
        private const val TAG = "ConnPool"
        private const val WARMUP_DELAY_MS = 200L   // wait a bit after first connect before pre-warming
    }

    private data class PooledSocket(
        val socket: Socket,
        val createdAtMs: Long = System.currentTimeMillis()
    )

    // key = "ip:port"
    private val pools = ConcurrentHashMap<String, LinkedBlockingQueue<PooledSocket>>()
    private val warmingUp = ConcurrentHashMap<String, Boolean>()

    private val warmupExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "conn-warmup").also { it.isDaemon = true }
    }

    @Volatile var alive = true

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Try to acquire a pre-warmed socket. Returns null if none available.
     * Never blocks — caller falls back to router.connect() on null.
     */
    fun acquire(dstIP: InetAddress, dstPort: Int): Socket? {
        val key = "${dstIP.hostAddress}:$dstPort"
        val queue = pools[key] ?: return null

        // Drain stale sockets from front
        while (true) {
            val pooled = queue.poll() ?: return null
            if (pooled.socket.isClosed || !pooled.socket.isConnected) continue
            if (System.currentTimeMillis() - pooled.createdAtMs > idleTimeoutMs) {
                runCatching { pooled.socket.close() }; continue
            }
            Log.d(TAG, "Pre-warmed socket acquired for $key")
            // Trigger background replenishment — only if not already warming up
            // (prevents infinite recursion: warmup→connect→acquire→warmup→…)
            if (warmingUp[key] != true) scheduleWarmup(dstIP, dstPort, key)
            return pooled.socket
        }
    }

    /**
     * Schedule background pre-warming for a destination that just had a
     * successful connection (SmartRouter found a good route for it).
     * Safe to call multiple times — deduplicates.
     */
    fun scheduleWarmup(dstIP: InetAddress, dstPort: Int, key: String? = null) {
        if (!alive) return
        val k = key ?: "${dstIP.hostAddress}:$dstPort"
        if (warmingUp[k] == true) return
        warmingUp[k] = true
        warmupExecutor.execute {
            try {
                Thread.sleep(WARMUP_DELAY_MS)
                val queue = pools.getOrPut(k) { LinkedBlockingQueue(maxPerDest) }
                val needed = maxPerDest - queue.size
                repeat(needed) {
                    if (!alive) return@repeat
                    val sock = router.connect(dstIP, dstPort) ?: return@repeat
                    if (!queue.offer(PooledSocket(sock))) {
                        runCatching { sock.close() }  // queue full, discard
                    }
                }
                Log.d(TAG, "Pre-warmed ${queue.size} sockets for $k")
            } catch (_: Exception) {}
            finally { warmingUp.remove(k) }
        }
    }

    /** Evict sockets that have been idle too long. Call every ~30s. */
    fun evictIdle() {
        val now = System.currentTimeMillis()
        for ((key, queue) in pools) {
            val iter = queue.iterator()
            while (iter.hasNext()) {
                val p = iter.next()
                if (p.socket.isClosed || now - p.createdAtMs > idleTimeoutMs) {
                    iter.remove(); runCatching { p.socket.close() }
                }
            }
            if (queue.isEmpty()) pools.remove(key)
        }
    }

    fun stopAll() {
        alive = false
        warmupExecutor.shutdownNow()
        for (queue in pools.values) {
            while (true) {
                val p = queue.poll() ?: break
                runCatching { p.socket.close() }
            }
        }
        pools.clear()
        warmingUp.clear()
    }

    fun totalPooled(): Int = pools.values.sumOf { it.size }
}
