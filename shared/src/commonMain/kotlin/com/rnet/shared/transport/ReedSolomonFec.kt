package com.rnet.shared.transport

/**
 * Systematic Reed-Solomon FEC over GF(2^8) with primitive polynomial 0x11D.
 * Generator matrix is Cauchy: M[i][j] = 1/(x_i XOR y_j) where
 *   x_i = i+1, y_j = dataShards+j+1 (all in GF(256), disjoint sets).
 *
 * Any k = dataShards out of n = dataShards+parityShards received shards
 * are sufficient to reconstruct the original data (40% loss tolerance at k=6, m=4).
 *
 * This is pure Kotlin commonMain — no platform imports.
 */
class ReedSolomonFec(val dataShards: Int, val parityShards: Int) {

    val totalShards = dataShards + parityShards

    // ---- GF(2^8) arithmetic (poly 0x11D) --------------------------------

    private val gfExp = IntArray(512)
    private val gfLog = IntArray(256)

    init {
        require(dataShards > 0 && parityShards > 0)
        require(dataShards + parityShards <= 255)
        buildTables()
    }

    private fun buildTables() {
        var x = 1
        for (i in 0 until 255) {
            gfExp[i] = x
            gfLog[x] = i
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D
        }
        for (i in 255 until 512) gfExp[i] = gfExp[i - 255]
        gfLog[0] = 0 // undefined but harmless sentinel
    }

    private fun gfMul(a: Int, b: Int): Int {
        if (a == 0 || b == 0) return 0
        return gfExp[gfLog[a] + gfLog[b]]
    }

    private fun gfInv(a: Int): Int {
        require(a != 0) { "GF inverse of 0 is undefined" }
        return gfExp[255 - gfLog[a]]
    }

    // ---- Cauchy parity matrix -------------------------------------------

    private fun cauchyElement(row: Int, col: Int): Int =
        gfInv((row + 1) xor (dataShards + col + 1))

    // Build the full (totalShards × dataShards) encoding matrix:
    // top k rows = identity (systematic), bottom m rows = Cauchy parity rows.
    private fun buildEncodingMatrix(): Array<IntArray> {
        val matrix = Array(totalShards) { IntArray(dataShards) }
        // identity part
        for (i in 0 until dataShards) matrix[i][i] = 1
        // Cauchy parity part
        for (i in 0 until parityShards) {
            for (j in 0 until dataShards) {
                matrix[dataShards + i][j] = cauchyElement(i, j)
            }
        }
        return matrix
    }

    // ---- Encoding -------------------------------------------------------

    /**
     * Encodes [dataShards] shards of equal [shardSize] bytes.
     * Returns a new array of [parityShards] parity byte arrays.
     * The caller is responsible for transmitting all dataShards + parityShards shards.
     */
    fun encode(dataShardArrays: Array<ByteArray>, shardSize: Int): Array<ByteArray> {
        require(dataShardArrays.size == dataShards)
        val parity = Array(parityShards) { ByteArray(shardSize) }
        for (i in 0 until parityShards) {
            for (j in 0 until dataShards) {
                val coeff = cauchyElement(i, j)
                val dst = parity[i]
                val src = dataShardArrays[j]
                for (b in 0 until shardSize) {
                    dst[b] = (dst[b].toInt() xor gfMul(coeff, src[b].toInt() and 0xFF)).toByte()
                }
            }
        }
        return parity
    }

    // ---- Decoding (erasure reconstruction) ------------------------------

    /**
     * Reconstructs missing shards in-place.
     * [allShards] must have exactly [totalShards] entries; null entries are missing.
     * Returns true if reconstruction succeeded (≥ dataShards present), false if not enough shards.
     */
    fun reconstruct(allShards: Array<ByteArray?>, shardSize: Int): Boolean {
        val present = allShards.count { it != null }
        if (present < dataShards) return false
        // Already complete?
        if (allShards.all { it != null }) return true

        val encodingMatrix = buildEncodingMatrix()

        // Pick the first dataShards present shards to form a square sub-system
        val subMatrix = Array(dataShards) { IntArray(dataShards) }
        val subShards = arrayOfNulls<ByteArray>(dataShards)
        var subRow = 0
        for (i in 0 until totalShards) {
            if (allShards[i] != null) {
                subMatrix[subRow] = encodingMatrix[i].copyOf()
                subShards[subRow] = allShards[i]
                subRow++
                if (subRow == dataShards) break
            }
        }

        // Invert sub-matrix via Gauss-Jordan over GF(2^8)
        val inverse = gaussianInverse(subMatrix) ?: return false

        // Recover all data shards
        val recovered = Array(dataShards) { row ->
            ByteArray(shardSize).also { out ->
                for (col in 0 until dataShards) {
                    val coeff = inverse[row][col]
                    val src = subShards[col]!!
                    for (b in 0 until shardSize) {
                        out[b] = (out[b].toInt() xor gfMul(coeff, src[b].toInt() and 0xFF)).toByte()
                    }
                }
            }
        }

        // Write recovered data shards back
        for (i in 0 until dataShards) {
            if (allShards[i] == null) allShards[i] = recovered[i]
        }

        // Recompute any missing parity shards
        for (i in 0 until parityShards) {
            if (allShards[dataShards + i] == null) {
                val p = ByteArray(shardSize)
                for (j in 0 until dataShards) {
                    val coeff = cauchyElement(i, j)
                    val src = allShards[j]!!
                    for (b in 0 until shardSize) {
                        p[b] = (p[b].toInt() xor gfMul(coeff, src[b].toInt() and 0xFF)).toByte()
                    }
                }
                allShards[dataShards + i] = p
            }
        }
        return true
    }

    private fun gaussianInverse(matrix: Array<IntArray>): Array<IntArray>? {
        val n = dataShards
        // Augment with identity
        val aug = Array(n) { row -> IntArray(2 * n).also { r ->
            matrix[row].copyInto(r, 0)
            r[n + row] = 1
        }}
        for (col in 0 until n) {
            // Find pivot
            var pivotRow = -1
            for (row in col until n) {
                if (aug[row][col] != 0) { pivotRow = row; break }
            }
            if (pivotRow == -1) return null
            val tmp = aug[col]; aug[col] = aug[pivotRow]; aug[pivotRow] = tmp
            // Scale pivot row
            val pivotVal = aug[col][col]
            val pivotInv = gfInv(pivotVal)
            for (j in 0 until 2 * n) aug[col][j] = gfMul(aug[col][j], pivotInv)
            // Eliminate column
            for (row in 0 until n) {
                if (row == col) continue
                val factor = aug[row][col]
                if (factor == 0) continue
                for (j in 0 until 2 * n) {
                    aug[row][j] = aug[row][j] xor gfMul(factor, aug[col][j])
                }
            }
        }
        return Array(n) { row -> aug[row].copyOfRange(n, 2 * n) }
    }
}
