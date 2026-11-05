package com.rnet.shared.transport

/**
 * Wire-format constants and helpers shared between Android and iOS.
 *
 * Frame header layout (12 bytes):
 *   [4B session_id] [4B seq] [1B shard_index] [1B total_shards] [2B shard_len]
 *
 * Followed by [shard_len] bytes of AES-256-GCM ciphertext (IV prepended).
 */
object TransportFrame {
    const val HEADER_SIZE = 12

    const val FEC_DATA_SHARDS = 6
    const val FEC_PARITY_SHARDS = 4
    const val FEC_TOTAL_SHARDS = FEC_DATA_SHARDS + FEC_PARITY_SHARDS  // 10

    const val MTU_GOOD = 1400   // RSRP > -90 dBm
    const val MTU_FAIR = 900    // RSRP -90..-105 dBm
    const val MTU_POOR = 512    // RSRP < -105 dBm

    fun encode(
        sessionId: Int,
        seq: Int,
        shardIndex: Int,
        totalShards: Int,
        payload: ByteArray
    ): ByteArray {
        val buf = ByteArray(HEADER_SIZE + payload.size)
        var offset = 0
        fun putInt(v: Int) {
            buf[offset++] = (v ushr 24).toByte()
            buf[offset++] = (v ushr 16).toByte()
            buf[offset++] = (v ushr 8).toByte()
            buf[offset++] = v.toByte()
        }
        putInt(sessionId)
        putInt(seq)
        buf[offset++] = shardIndex.toByte()
        buf[offset++] = totalShards.toByte()
        buf[offset++] = (payload.size ushr 8).toByte()
        buf[offset++] = payload.size.toByte()
        payload.copyInto(buf, offset)
        return buf
    }

    data class ParsedFrame(
        val sessionId: Int,
        val seq: Int,
        val shardIndex: Int,
        val totalShards: Int,
        val shardData: ByteArray
    )

    fun decode(raw: ByteArray): ParsedFrame? {
        if (raw.size < HEADER_SIZE) return null
        var offset = 0
        fun getInt(): Int =
            ((raw[offset++].toInt() and 0xFF) shl 24) or
            ((raw[offset++].toInt() and 0xFF) shl 16) or
            ((raw[offset++].toInt() and 0xFF) shl 8) or
            (raw[offset++].toInt() and 0xFF)
        val sessionId = getInt()
        val seq = getInt()
        val shardIndex = raw[offset++].toInt() and 0xFF
        val totalShards = raw[offset++].toInt() and 0xFF
        val shardLen = ((raw[offset++].toInt() and 0xFF) shl 8) or (raw[offset++].toInt() and 0xFF)
        if (raw.size < HEADER_SIZE + shardLen) return null
        val shardData = raw.copyOfRange(HEADER_SIZE, HEADER_SIZE + shardLen)
        return ParsedFrame(sessionId, seq, shardIndex, totalShards, shardData)
    }
}
