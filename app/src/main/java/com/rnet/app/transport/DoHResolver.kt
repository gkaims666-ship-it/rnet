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
 * Two resolution paths:
 *   • [resolveViaSocks] — tunnels the DoH query through the Psiphon SOCKS5
 *     exit. The DNS query leaves the device *inside the encrypted tunnel*, so
 *     the local network cannot see it, block it by SNI, or return a poisoned
 *     answer for a censored domain. This is the honest path and should be
 *     preferred whenever a tunnel is up.
 *   • [resolveParallel] / [resolve] — DoH over a direct (protect()ed) socket.
 *     Faster, but the local censor can block it (the TLS SNI to the DoH host
 *     is visible) and, if it falls through to plain UDP, poison it.
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
     * Resolve a raw DNS query using DoH over DIRECT (protect()ed) sockets —
     * PARALLEL edition. All endpoints probed simultaneously; first response wins.
     *
     * Prefer [resolveViaSocks] when a tunnel is up: direct DoH can be blocked by
     * the local network (the TLS SNI to the DoH host is visible in plaintext).
     */
    fun resolveParallel(
        query: ByteArray,
        protect: ((Socket) -> Boolean)? = null
    ): ByteArray? = probeParallel(query) { ep -> connectDirect(ep, protect) }

    /**
     * Resolve a raw DNS query by tunnelling the DoH request through the SOCKS5
     * proxy on 127.0.0.1:[socksPort] (the active Psiphon exit). The DNS query is
     * resolved at the exit, so the local network cannot see it, block it by SNI,
     * or return a poisoned answer for a censored domain — this is what makes
     * blocked domains resolve to their real addresses.
     *
     * The socket to the local SOCKS port is protect()ed so it bypasses the tun
     * (no routing loop); the SOCKS proxy itself carries the query upstream.
     */
    fun resolveViaSocks(
        query: ByteArray,
        socksPort: Int,
        protect: ((Socket) -> Boolean)? = null
    ): ByteArray? = probeParallel(query) { ep -> connectViaSocks(ep, socksPort, protect) }

    /**
     * Sequential fallback resolve over direct sockets (kept for compatibility).
     */
    fun resolve(
        query: ByteArray,
        protect: ((Socket) -> Boolean)? = null
    ): ByteArray? {
        for (ep in endpoints) {
            try {
                val sock = connectDirect(ep, protect) ?: continue
                val resp = tlsExchange(sock, ep, query)
                if (resp != null) return resp
            } catch (e: Exception) {
                Log.d(TAG, "DoH ${ep.ip} failed: ${e.message}")
            }
        }
        return null
    }

    // ── Internal probe machinery ────────────────────────────────────────────

    /** Probe all endpoints in parallel using [connect]; first valid answer wins. */
    private fun probeParallel(query: ByteArray, connect: (DoHEndpoint) -> Socket?): ByteArray? {
        val result = LinkedBlockingQueue<ByteArray>(1)
        val futures = endpoints.map { ep ->
            dohPool.submit {
                try {
                    val sock = connect(ep) ?: return@submit
                    val resp = tlsExchange(sock, ep, query)
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

    /** Open a direct (protect()ed) TCP socket to the DoH endpoint IP. */
    private fun connectDirect(ep: DoHEndpoint, protect: ((Socket) -> Boolean)?): Socket? {
        val raw = Socket()
        return try {
            protect?.invoke(raw)
            raw.soTimeout = TIMEOUT_MS
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(ep.ip, ep.port), TIMEOUT_MS)
            raw
        } catch (e: Exception) {
            runCatching { raw.close() }
            null
        }
    }

    /**
     * Open a socket to the local SOCKS5 proxy (protect()ed so it bypasses the
     * tun) and issue a SOCKS5 CONNECT to the DoH endpoint IP:port. Returns the
     * tunnelled socket ready for TLS, or null on failure.
     */
    private fun connectViaSocks(ep: DoHEndpoint, socksPort: Int, protect: ((Socket) -> Boolean)?): Socket? {
        val raw = Socket()
        return try {
            protect?.invoke(raw)
            raw.soTimeout = TIMEOUT_MS
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress("127.0.0.1", socksPort), TIMEOUT_MS)
            if (!socks5Connect(raw, ep.ip, ep.port)) { raw.close(); return null }
            raw
        } catch (e: Exception) {
            runCatching { raw.close() }
            null
        }
    }

    /** Minimal SOCKS5 no-auth CONNECT to a numeric IPv4 host:port. */
    private fun socks5Connect(sock: Socket, ipv4: String, port: Int): Boolean {
        val din = DataInputStream(sock.inputStream)
        val out = sock.outputStream
        // Greeting: VER=5, 1 method, NO-AUTH
        out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
        val greet = ByteArray(2); din.readFully(greet)
        if (greet[0] != 0x05.toByte() || greet[1] != 0x00.toByte()) return false
        // CONNECT: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), 4-byte addr, 2-byte port
        val octets = ipv4.split(".").mapNotNull { it.toIntOrNull() }
        if (octets.size != 4) return false
        val req = ByteArray(10)
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01
        for (i in 0 until 4) req[4 + i] = (octets[i] and 0xFF).toByte()
        req[8] = (port shr 8).toByte(); req[9] = (port and 0xFF).toByte()
        out.write(req); out.flush()
        // Reply: VER REP RSV ATYP + bound addr/port — read header, drain addr
        val hdr = ByteArray(4); din.readFully(hdr)
        if (hdr[0] != 0x05.toByte() || hdr[1] != 0x00.toByte()) return false
        when (hdr[3].toInt() and 0xFF) {
            0x01 -> din.readFully(ByteArray(4 + 2))
            0x04 -> din.readFully(ByteArray(16 + 2))
            0x03 -> { val len = din.read() and 0xFF; din.readFully(ByteArray(len + 2)) }
            else -> return false
        }
        return true
    }

    /**
     * Run the DoH HTTPS exchange (TLS handshake + HTTP POST + read body) over an
     * already-connected socket whose stream reaches the DoH endpoint (directly or
     * via SOCKS). Closes the socket. Returns the raw DNS response bytes or null.
     */
    private fun tlsExchange(connected: Socket, ep: DoHEndpoint, query: ByteArray): ByteArray? {
        return try {
            val tlsFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            // autoClose=true means closing the SSLSocket also closes `connected`.
            val tls = tlsFactory.createSocket(connected, ep.sni, ep.port, true) as SSLSocket
            tls.soTimeout = TIMEOUT_MS
            // Explicit SNI so the server presents the right certificate.
            tls.sslParameters = tls.sslParameters.also { p ->
                p.serverNames = listOf(SNIHostName(ep.sni))
            }
            tls.startHandshake()

            tls.use { ssl ->
                val out: OutputStream = ssl.outputStream
                val din = DataInputStream(ssl.inputStream)

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

                if (contentLength in 1..65535) {
                    val respBytes = ByteArray(contentLength)
                    din.readFully(respBytes)
                    respBytes
                } else if (contentLength < 0) {
                    ssl.inputStream.readBytes().takeIf { it.isNotEmpty() }
                } else null
            }
        } catch (e: Exception) {
            runCatching { connected.close() }
            null
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
     * Used only if both DoH paths fail. WARNING: plain UDP DNS is visible to the
     * local network and can be poisoned for censored domains — it is the last
     * resort precisely because of that.
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
