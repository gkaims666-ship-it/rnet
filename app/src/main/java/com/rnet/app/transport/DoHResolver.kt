package com.rnet.app.transport

import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * DoHResolver — DNS-over-HTTPS client.
 *
 * Sends DNS queries as HTTPS POST requests to Cloudflare (1.1.1.1/dns-query)
 * and Google (8.8.8.8/dns-query) with automatic fallback.
 *
 * Why: Plain UDP DNS on port 53 is trivially intercepted and poisoned by ISPs
 * to block access to sites. DoH encrypts DNS queries inside TLS, making them
 * indistinguishable from regular HTTPS traffic — the ISP cannot block or
 * tamper with them without blocking all HTTPS.
 *
 * Usage: call resolve() with a raw DNS query packet and get a raw DNS response.
 * The VPN's UDP handler passes DNS packets here instead of to 1.1.1.1:53.
 */
object DoHResolver {

    private const val TAG = "DoHResolver"
    private const val TIMEOUT_MS = 5000

    // DoH endpoints — tried in order, first success wins
    private val endpoints = listOf(
        "https://1.1.1.1/dns-query",
        "https://1.0.0.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://8.8.4.4/dns-query",
        "https://dns.google/dns-query"
    )

    // Thread pool for parallel DoH probes (audit fix #8)
    private val dohPool = Executors.newCachedThreadPool { r ->
        Thread(r, "doh-probe").also { it.isDaemon = true }
    }

    /**
     * Resolve a raw DNS query using DNS-over-HTTPS — PARALLEL edition.
     * All endpoints are probed simultaneously; whichever responds first wins.
     * Worst-case latency = single endpoint timeout (5s), not 5×5s = 25s.
     */
    fun resolveParallel(query: ByteArray): ByteArray? {
        val result = LinkedBlockingQueue<ByteArray>(1)
        val futures = endpoints.map { url ->
            dohPool.submit {
                try {
                    val conn = URL(url).openConnection() as HttpsURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Content-Type", "application/dns-message")
                    conn.setRequestProperty("Accept", "application/dns-message")
                    conn.connectTimeout = TIMEOUT_MS
                    conn.readTimeout    = TIMEOUT_MS
                    conn.doOutput = true
                    conn.outputStream.use { it.write(query) }
                    if (conn.responseCode == 200) {
                        val resp = conn.inputStream.use { it.readBytes() }
                        if (resp.isNotEmpty()) result.offer(resp)
                    }
                    conn.disconnect()
                } catch (e: Exception) {
                    Log.d(TAG, "DoH $url failed: ${e.message}")
                }
            }
        }
        val answer = result.poll(TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
        futures.forEach { it.cancel(true) }
        return answer
    }

    /**
     * Sequential fallback resolve (kept for compatibility).
     */
    fun resolve(query: ByteArray, protect: ((java.net.Socket) -> Unit)? = null): ByteArray? {
        for (url in endpoints) {
            try {
                val conn = URL(url).openConnection() as HttpsURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/dns-message")
                conn.setRequestProperty("Accept", "application/dns-message")
                conn.connectTimeout = TIMEOUT_MS
                conn.readTimeout    = TIMEOUT_MS
                conn.doOutput = true
                conn.outputStream.use { it.write(query) }
                val code = conn.responseCode
                if (code == 200) {
                    val resp = conn.inputStream.use { it.readBytes() }
                    if (resp.isNotEmpty()) return resp
                }
                conn.disconnect()
            } catch (e: Exception) {
                Log.d(TAG, "DoH $url failed: ${e.message}")
            }
        }
        return null
    }

    /**
     * Fallback: plain UDP DNS to upstream resolvers that may still work.
     * Used if DoH fails (e.g. HTTPS itself is blocked).
     */
    fun resolveUdp(query: ByteArray, protect: (DatagramSocket) -> Unit): ByteArray? {
        val upstreams = listOf(
            InetSocketAddress("1.1.1.1", 53),
            InetSocketAddress("8.8.8.8", 53),
            InetSocketAddress("9.9.9.9", 53),
            InetSocketAddress("208.67.222.222", 53)  // OpenDNS
        )
        for (addr in upstreams) {
            try {
                val sock = DatagramSocket()
                protect(sock)
                sock.soTimeout = 3000
                sock.send(DatagramPacket(query, query.size, addr))
                val rb = ByteArray(2048)
                val rp = DatagramPacket(rb, rb.size)
                sock.receive(rp)
                sock.close()
                return rb.copyOf(rp.length)
            } catch (_: Exception) {}
        }
        return null
    }
}
