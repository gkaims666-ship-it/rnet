package com.rnet.app.transport

/**
 * ReedSolomonFec — systematic (k, n) Reed-Solomon over GF(2^8).
 *
 * Uses the Cauchy matrix construction so that the first k symbols of an
 * encoded block are identical to the input (systematic form). Up to (n-k)
 * erasures can be corrected by any k received symbols.
 *
 * Default configuration: k=10 data shards, n=14 total (4 parity shards) →
 * survives 4/14 ≈ 28% random shard loss. For 40% physical packet loss budget
 * set k=6, n=10 (40% parity).
 *
 * This is a pure-Kotlin portable implementation; no JNI required.
 * Performance is adequate for ≤64 KB frame sizes on any tier device.
 */
class ReedSolomonFec(val dataShards: Int, val parityShards: Int) {

    val totalShards: Int = dataShards + parityShards

    // GF(2^8) with primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D)
    private val GF_EXP = IntArray(512)
    private val GF_LOG = IntArray(256)

    init {
        require(dataShards in 1..255 && totalShards <= 255)
        buildGfTables()
    }

    private fun buildGfTables() {
        var x = 1
        for (i in 0 until 255) {
            GF_EXP[i] = x
            GF_LOG[x] = i
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D
        }
        for (i in 255 until 512) GF_EXP[i] = GF_EXP[i - 255]
        GF_LOG[0] = 0  // log(0) undefined; guarded in multiply
    }

    private fun gfMul(a: Int, b: Int): Int {
        if (a == 0 || b == 0) return 0
        return GF_EXP[GF_LOG[a] + GF_LOG[b]]
    }

    private fun gfInv(a: Int): Int {
        require(a != 0) { "GF inverse of 0 is undefined" }
        return GF_EXP[255 - GF_LOG[a]]
    }

    // Vandermonde parity matrix rows (parityShards × dataShards)
    private val parityMatrix: Array<IntArray> by lazy { buildParityMatrix() }

    private fun buildParityMatrix(): Array<IntArray> {
        // Cauchy matrix: M[i][j] = 1 / (x_i XOR y_j)
        // x_i = i+1, y_j = dataShards + j + 1  (keep sets disjoint)
        return Array(parityShards) { i ->
            IntArray(dataShards) { j ->
                gfInv((i + 1) xor (dataShards + j + 1))
            }
        }
    }

    // ----- Encoding -----

    /**
     * Encode [dataShards] equal-length byte arrays into [parityShards] parity arrays.
     * Input shards must all have length [shardSize].
     */
    fun encode(shards: Array<ByteArray>, shardSize: Int): Array<ByteArray> {
        require(shards.size == dataShards)
        val parity = Array(parityShards) { ByteArray(shardSize) }
        for (p in 0 until parityShards) {
            for (d in 0 until dataShards) {
                val coeff = parityMatrix[p][d]
                val src   = shards[d]
                val dst   = parity[p]
                for (b in 0 until shardSize) {
                    dst[b] = (dst[b].toInt() xor gfMul(coeff, src[b].toInt() and 0xFF)).toByte()
                }
            }
        }
        return parity
    }

    // ----- Decoding / reconstruction -----

    /**
     * Reconstruct missing shards in-place.
     *
     * @param allShards  Array of size [totalShards]. Null entries = lost shards.
     * @param shardSize  Byte length of each shard.
     * @return true if reconstruction succeeded (≥ dataShards present).
     */
    fun reconstruct(allShards: Array<ByteArray?>, shardSize: Int): Boolean {
        val present = allShards.indices.filter { allShards[it] != null }
        if (present.size < dataShards) return false
        if (present.size == totalShards) return true  // nothing lost

        val subMatrix = Array(dataShards) { r -> IntArray(dataShards) }
        val srcShards  = Array(dataShards) { ByteArray(0) }
        for (r in 0 until dataShards) {
            val idx = present[r]
            srcShards[r] = allShards[idx]!!
            if (idx < dataShards) {
                // Data shard row: identity
                subMatrix[r][idx] = 1
            } else {
                // Parity shard row: copy from parity matrix
                val pi = idx - dataShards
                subMatrix[r] = parityMatrix[pi].copyOf()
            }
        }

        val invMatrix = gaussianInverse(subMatrix) ?: return false

        // Recover all data shards
        for (d in 0 until dataShards) {
            if (allShards[d] != null) continue
            val out = ByteArray(shardSize)
            for (s in 0 until dataShards) {
                val coeff = invMatrix[d][s]
                val src   = srcShards[s]
                for (b in 0 until shardSize) {
                    out[b] = (out[b].toInt() xor gfMul(coeff, src[b].toInt() and 0xFF)).toByte()
                }
            }
            allShards[d] = out
        }
        return true
    }

    // Gauss-Jordan inverse over GF(2^8)
    private fun gaussianInverse(mat: Array<IntArray>): Array<IntArray>? {
        val n = mat.size
        val m = Array(n) { r -> mat[r].copyOf() + IntArray(n) { c -> if (c == r) 1 else 0 } }
        for (col in 0 until n) {
            // Find pivot
            var pivot = -1
            for (row in col until n) if (m[row][col] != 0) { pivot = row; break }
            if (pivot < 0) return null
            val tmp = m[col]; m[col] = m[pivot]; m[pivot] = tmp
            val scale = gfInv(m[col][col])
            for (j in 0 until 2 * n) m[col][j] = gfMul(m[col][j], scale)
            for (row in 0 until n) {
                if (row == col) continue
                val factor = m[row][col]
                if (factor == 0) continue
                for (j in 0 until 2 * n) m[row][j] = m[row][j] xor gfMul(factor, m[col][j])
            }
        }
        return Array(n) { r -> m[r].copyOfRange(n, 2 * n) }
    }
}
