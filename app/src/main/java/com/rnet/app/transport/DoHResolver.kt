package com.rnet.app.transport

import android.util.Log
import java.io.DataInputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * DoHResolver — DNS-over-HTTPS client.
 *
 * Uses numeric IP addresses for DoH endpoints (1.1.1.1, 8.8.8.8) so no
 * hostname resolution is needed to reach them — avoiding a bootstrap
 * recursion problem.
 *
 * CRITICAL: When called from inside the VPN service, callers MUST supply a
 * [protect] callback (VpnService.protect) so the underlying TCP sockets
 * bypass the VPN tun. Without this, the DoH connection goes through the
 * tun → handler → another DoH call → infinite loop → deadlock.
 *
 * Uses raw TLS sockets (not HttpsURLConnection) so we can call protect()
 * on the underlying socket before connecting.
 */
object DoHResolver {

    private const val TAG = "DoHResolver"
    private const val TIMEOUT_MS = 5000

    // Endpoints identified by IP:port — no hostname resolution needed.
    // SNI is set to the domain name for TLS handshake; the actual TCP
    // connection goes to the numeric IP, bypassing any DNS lookup.
    private data class DoHEndpoint(val ip: String, val port: Int, val sni: String, val path: String)

    private val endpoints = listOf(
        DoHEndpoint("1.1.1.1",   443, "cloudflare-dns.com", "/dns-query"),
        DoHEndpoint("1.0.0.1",   443, "cloudflare-dns.com", "/dns-query"),
        DoHEndpoint("8.8.8.8",   443, "dns.google",         "/dns-query"),
        DoHEndpoint("8.8.4.4",   443, "dns.google",         "/dns-query")
    )

    // Thread pool for parallel probes
    private val dohPool = Executors.newCachedThreadPool { r ->
        Thread(r, "doh-probe").also { it.isDaemon = true }
    }

    /**
     * Resolve a raw DNS query using DoH — PARALLEL edition.
     * All endpoints probed simultaneously; first response wins.
     *
     * @param query    Raw DNS wire-format query bytes
     * @param protect  VpnService.protect lambda — REQUIRED when called from
     *                 inside the VPN service to prevent routing loops.
     *                 Pass null only when VPN is not active.
     */
    fun resolveParallel(
        query: ByteArray,
        protect: ((Socket) -> Boolean)? = null
    ): ByteArray? {
        val result = LinkedBlockingQueue<ByteArray>(1)
        val futures = endpoints.map { ep ->
            dohPool.submit {
                try {
                    val resp = queryEndpoint(ep, query, protect)
                    if (resp != null) result.offer(resp)
                } catch (e: Exception) {
                    Log.d(TAG, "DoH ${ep.ip} failed: ${e.message}")
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
    fun resolve(
        query: ByteArray,
        protect: ((Socket) -> Boolean)? = null
    ): ByteArray? {
        for (ep in endpoints) {
            try {
                val resp = queryEndpoint(ep, query, protect)
                if (resp != null) return resp
            } catch (e: Exception) {
                Log.d(TAG, "DoH ${ep.ip} failed: ${e.message}")
            }
        }
        return null
    }

    /**
     * Query a single DoH endpoint using a raw TLS socket.
     * protect() is called on the underlying TCP socket BEFORE connect()
     * so the connection bypasses the VPN tun entirely.
     */
    private fun queryEndpoint(
        ep: DoHEndpoint,
        query: ByteArray,
        protect: ((Socket) -> Boolean)?
    ): ByteArray? {
        val rawSock = Socket()
        return try {
            // Protect BEFORE connecting — this makes the socket bypass the VPN tun
            // and go directly to the network. Without this, when called from inside
            // the VPN service, the connection would loop back through the tun.
            protect?.invoke(rawSock)

            rawSock.soTimeout = TIMEOUT_MS
            rawSock.tcpNoDelay = true
            rawSock.connect(InetSocketAddress(ep.ip, ep.port), TIMEOUT_MS)

            // Wrap in TLS on top of the already-connected and already-protected socket.
            // autoClose=true means closing the SSLSocket also closes rawSock.
            val tlsFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val tls = tlsFactory.createSocket(rawSock, ep.sni, ep.port, true) as SSLSocket
            tls.soTimeout = TIMEOUT_MS
            // Set explicit SNI so the server presents the right certificate
            tls.sslParameters = tls.sslParameters.also { p ->
                p.serverNames = listOf(SNIHostName(ep.sni))
            }
            tls.startHandshake()

            tls.use { ssl ->
                val out: OutputStream = ssl.outputStream
                val din = DataInputStream(ssl.inputStream)

                // Build HTTP/1.1 POST request
                val request = buildString {
                    append("POST ${ep.path} HTTP/1.1\r\n")
                    append("Host: ${ep.sni}\r\n")
                    append("Content-Type: application/dns-message\r\n")
                    append("Accept: application/dns-message\r\n")
                    append("Content-Length: ${query.size}\r\n")
                    append("Connection: close\r\n")
                    append("\r\n")
                }
                out.write(request.toByteArray(Charsets.US_ASCII))
                out.write(query)
                out.flush()

                // Read HTTP response — parse status line and Content-Length header
                val statusLine = readLine(din) ?: return@use null
                if (!statusLine.contains("200")) return@use null

                var contentLength = -1
                while (true) {
                    val header = readLine(din) ?: break
                    if (header.isEmpty()) break  // blank line = end of headers
                    if (header.lowercase().startsWith("content-length:")) {
                        contentLength = header.substringAfter(":").trim().toIntOrNull() ?: -1
                    }
                }

                // Read response body
                if (contentLength in 1..65535) {
                    val respBytes = ByteArray(contentLength)
                    din.readFully(respBytes)
                    respBytes
                } else if (contentLength < 0) {
                    // No Content-Length: read until connection closes
                    ssl.inputStream.readBytes().takeIf { it.isNotEmpty() }
                } else null
            }
        } catch (e: Exception) {
            runCatching { rawSock.close() }
            throw e   // re-throw so caller can log and try next endpoint
        }
    }

    /** Read one CRLF-terminated line from a DataInputStream. */
    private fun readLine(din: DataInputStream): String? {
        val sb = StringBuilder()
        var prev = 0
        while (true) {
            val b = try { din.read() } catch (_: Exception) { return null }
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (prev == '\r'.code && b == '\n'.code) {
                return sb.dropLast(1).toString()  // drop the \r
            }
            sb.append(b.toChar())
            prev = b
        }
    }

    /**
     * Fallback: plain UDP DNS to upstream resolvers.
     * Used if DoH fails (e.g. HTTPS itself is blocked).
     * protect() must be supplied when called from inside the VPN service.
     */
    fun resolveUdp(
        query: ByteArray,
        protect: (DatagramSocket) -> Unit
    ): ByteArray? {
        val upstreams = listOf(
            InetSocketAddress("1.1.1.1", 53),
            InetSocketAddress("8.8.8.8", 53),
            InetSocketAddress("9.9.9.9", 53)
        )
        for (addr in upstreams) {
            try {
                // Bug fix: use `use{}` so the socket is always closed, even
                // when sock.receive() throws (e.g. SocketTimeoutException).
                // Previously the socket leaked on any exception after creation.
                DatagramSocket().use { sock ->
                    protect(sock)
                    sock.soTimeout = 3000
                    sock.send(DatagramPacket(query, query.size, addr))
                    val rb = ByteArray(2048)
                    val rp = DatagramPacket(rb, rb.size)
                    sock.receive(rp)
                    return rb.copyOf(rp.length)
                }
            } catch (_: Exception) {}
        }
        return null
    }
}
