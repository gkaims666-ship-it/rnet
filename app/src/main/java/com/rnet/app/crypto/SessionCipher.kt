package com.rnet.app.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

/**
 * SessionCipher — AES-256-GCM AEAD encryption for all RNET transport frames.
 *
 * Each invocation generates a fresh random 12-byte IV (nonce) and prepends it
 * to the ciphertext output. Callers must never reuse a session key across
 * more than 2^32 messages; the transport layer re-keys on handshake replay.
 *
 * Wire format of encrypt() output:
 *   [ 12 bytes IV | N bytes ciphertext+tag (tag = 16 bytes) ]
 */
class SessionCipher(sessionKey: ByteArray) {

    init {
        require(sessionKey.size == 32) { "Session key must be 256-bit (32 bytes)" }
    }

    private val keySpec = SecretKeySpec(sessionKey, "AES")
    private val rng = SecureRandom()

    companion object {
        private const val GCM_IV_LEN   = 12
        private const val GCM_TAG_BITS = 128
    }

    fun encrypt(plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        val iv = ByteArray(GCM_IV_LEN).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_BITS, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        return iv + ct
    }

    fun decrypt(payload: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(payload.size >= GCM_IV_LEN + 16) { "Payload too short" }
        val iv = payload.copyOfRange(0, GCM_IV_LEN)
        val ct = payload.copyOfRange(GCM_IV_LEN, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_BITS, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ct)
    }
}
