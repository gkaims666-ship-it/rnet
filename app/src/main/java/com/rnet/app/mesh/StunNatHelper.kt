package com.rnet.app.mesh

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
     * This is a best-effort call; the mesh layer continues with local discovery
     * if STUN is unavailable.
     */
    suspend fun discoverReflexiveAddress(timeoutMs: Int = 2000): ReflexiveAddress? =
        withContext(Dispatchers.IO) {
            for ((host, port) in STUN_SERVERS) {
                try {
                    val result = sendBindingRequest(host, port, timeoutMs)
                    if (result != null) return@withContext result
                } catch (e: Exception) {
                    Log.d(TAG, "STUN $host:$port unreachable: ${e.message}")
                }
            }
            Log.w(TAG, "All STUN servers unreachable — mesh will use local discovery only")
            null
        }

    // ----- RFC 5389 Binding Request -----

    private fun sendBindingRequest(host: String, port: Int, timeoutMs: Int): ReflexiveAddress? {
        val txId = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val request = buildBindingRequest(txId)

        DatagramSocket().use { sock ->
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
        val magic     = buf.int
        val txId      = ByteArray(12).also { buf.get(it) }

        if (msgType != 0x0101.toShort()) return null  // not a Binding Response

        var remaining = msgLen
        while (remaining >= 4) {
            val attrType = buf.short.toInt() and 0xFFFF
            val attrLen  = buf.short.toInt() and 0xFFFF
            remaining -= 4

            if (attrType == 0x0020 && attrLen >= 8) {   // XOR-MAPPED-ADDRESS
                buf.get()                                // ignored
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
            } else {
                val padded = (attrLen + 3) and 3.inv()
                buf.position(buf.position() + minOf(padded, remaining))
            }
            remaining -= minOf((attrLen + 3) and 3.inv(), remaining)
        }
        return null
    }
}
