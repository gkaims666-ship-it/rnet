package com.rnet.app.mesh

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * StunNatHelper — RFC 5389 STUN Binding Request for peer-to-peer NAT traversal.
 *
 * Used exclusively by the mesh layer to discover the device's reflexive (public)
 * address so that mesh peers on different NATs can establish direct connections
 * without routing all traffic through the relay server.
 *
 * Uses publicly available, standards-compliant STUN servers operated by Google
 * and Cloudflare. These servers are specifically designed and maintained for
 * NAT traversal use. No application payload is sent — only the RFC 5389
 * Binding Request/Response messages defined by the STUN protocol.
 *
 * STUN is NOT used for the uplink transport engine — the transport engine
 * connects only to the user-configured relay server.
 */
object StunNatHelper {

    private val TAG = "StunNatHelper"

    /**
     * Public STUN servers: all are freely available, standards-compliant,
     * and explicitly provided for NAT traversal use by their operators.
     */
    private val STUN_SERVERS = listOf(
        "stun.l.google.com"    to 19302,
        "stun1.l.google.com"   to 19302,
        "stun.cloudflare.com"  to 3478,
    )

    data class ReflexiveAddress(val ip: String, val port: Int)

    /**
     * Performs a STUN Binding Request to discover the device's public IP:port.
     * Returns null if all STUN servers are unreachable (e.g. offline or restricted).
     *
     * @param timeoutMs   Per-server socket timeout in milliseconds.
     * @param vpnService  MUST be supplied when a VPN tun is active. Without protect()
     *                    the STUN UDP socket is routed back through the tun interface
     *                    and loops forever. VpnService.protect(DatagramSocket) exempts
     *                    the socket from tun routing.
     *
     * This is a best-effort call; the mesh layer continues with local discovery
     * if STUN is unavailable.
     */
    suspend fun discoverReflexiveAddress(
        timeoutMs: Int = 2000,
        vpnService: VpnService? = null
    ): ReflexiveAddress? =
        withContext(Dispatchers.IO) {
            for ((host, port) in STUN_SERVERS) {
                try {
                    val result = sendBindingRequest(host, port, timeoutMs, vpnService)
                    if (result != null) return@withContext result
                } catch (e: Exception) {
                    Log.d(TAG, "STUN $host:$port unreachable: ${e.message}")
                }
            }
            Log.w(TAG, "All STUN servers unreachable — mesh will use local discovery only")
            null
        }

    // ----- RFC 5389 Binding Request -----

    private fun sendBindingRequest(
        host: String,
        port: Int,
        timeoutMs: Int,
        vpnService: VpnService?
    ): ReflexiveAddress? {
        val txId = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val request = buildBindingRequest(txId)

        DatagramSocket().use { sock ->
            // CRITICAL: protect the UDP socket from the VPN tun routing loop.
            // VpnService.protect(DatagramSocket) is available since API 21.
            // Without this, when the VPN is active, the STUN UDP packet is
            // routed back into the tun fd and never reaches the STUN server.
            vpnService?.protect(sock)

            sock.soTimeout = timeoutMs
            val addr = InetAddress.getByName(host)
            sock.send(DatagramPacket(request, request.size, addr, port))

            val buf = ByteArray(512)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            return parseBindingResponse(buf, txId)
        }
    }

    /** RFC 5389 §6 — 20-byte STUN header + no attributes */
    private fun buildBindingRequest(txId: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(20)
        buf.putShort(0x0001)                // Message Type: Binding Request
        buf.putShort(0x0000)                // Message Length: 0 attributes
        buf.putInt(0x2112A442.toInt())      // Magic Cookie
        buf.put(txId)
        return buf.array()
    }

    /** Parse XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001) from response */
    private fun parseBindingResponse(data: ByteArray, expectedTxId: ByteArray): ReflexiveAddress? {
        val buf = ByteBuffer.wrap(data)
        val msgType   = buf.short
        val msgLen    = buf.short.toInt() and 0xFFFF
        @Suppress("UNUSED_VARIABLE")
        val magic     = buf.int
        @Suppress("UNUSED_VARIABLE")
        val txId      = ByteArray(12).also { buf.get(it) }

        if (msgType != 0x0101.toShort()) return null  // not a Binding Response

        var remaining = msgLen
        while (remaining >= 4) {
            val attrType = buf.short.toInt() and 0xFFFF
            val attrLen  = buf.short.toInt() and 0xFFFF
            remaining -= 4   // consumed type(2) + length(2)

            if (attrType == 0x0020 && attrLen >= 8) {   // XOR-MAPPED-ADDRESS
                buf.get()                                // ignored (reserved)
                val family = buf.get().toInt() and 0xFF
                if (family == 0x01) {                   // IPv4
                    val xPort = (buf.short.toInt() and 0xFFFF) xor 0x2112
                    val xIp   = buf.int xor 0x2112A442.toInt()
                    val ip = "%d.%d.%d.%d".format(
                        (xIp ushr 24) and 0xFF,
                        (xIp ushr 16) and 0xFF,
                        (xIp ushr  8) and 0xFF,
                         xIp          and 0xFF
                    )
                    return ReflexiveAddress(ip, xPort)
                }
                // IPv6 or unrecognised family — skip the rest of this attribute
                val consumed = 8  // family(1) + reserved(1) + port(2) + IPv4(4) already read for IPv4;
                                  // for other families, skip the declared length minus the 2 we read
                val skip = attrLen - 2  // already consumed: reserved(1) + family(1)
                val padded = (attrLen + 3) and 3.inv()
                val toSkip = minOf(padded - 2, buf.remaining())
                if (toSkip > 0) buf.position(buf.position() + toSkip)
                remaining -= minOf(padded, remaining)
            } else {
                // Skip this attribute (padded to 4-byte boundary)
                val padded = (attrLen + 3) and 3.inv()
                val toSkip = minOf(padded, buf.remaining())
                if (toSkip > 0) buf.position(buf.position() + toSkip)
                remaining -= minOf(padded, remaining)
            }
        }
        return null
    }
}
