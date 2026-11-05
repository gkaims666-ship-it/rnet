package com.rnet.app.crypto

import android.util.Log
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HybridKeyExchange — ML-KEM-768 (CRYSTALS-Kyber) + X25519 hybrid key encapsulation.
 *
 * Architecture:
 *   shared_secret = KDF( X25519_shared || KEM_shared, transcript )
 *
 * ML-KEM-768 is provided via Bouncy Castle (bcprov-jdk18on) using the low-level
 * crypto API directly (the JCA wrapper's key params are package-private).
 * X25519 is provided via the Android/JVM built-in XDH provider.
 * The final 32-byte session key feeds the AES-256-GCM AEAD layer in SessionCipher.
 */
object HybridKeyExchange {

    private const val TAG = "HybridKEX"

    // -------------------------------------------------------------------------
    // X25519 (ECDH on Curve25519)
    // -------------------------------------------------------------------------

    fun generateX25519KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("XDH")
        kpg.initialize(ECGenParameterSpec("X25519"))
        return kpg.generateKeyPair()
    }

    fun x25519SharedSecret(localPrivate: java.security.PrivateKey, remotePub: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("XDH")
        ka.init(localPrivate)
        ka.doPhase(remotePub, true)
        return ka.generateSecret()
    }

    // -------------------------------------------------------------------------
    // ML-KEM-768 — raw Bouncy Castle crypto layer (avoids package-private JCA)
    // -------------------------------------------------------------------------

    /**
     * Wraps the raw Kyber key-pair so callers don't need BC imports.
     */
    data class KemKeyPair(
        val publicKey: org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters,
        val privateKey: org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters
    )

    fun generateKemKeyPair(): KemKeyPair {
        val gen = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator()
        gen.init(org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters(
            SecureRandom(),
            org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters.kyber768
        ))
        val kp = gen.generateKeyPair()
        return KemKeyPair(
            publicKey  = kp.public  as org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters,
            privateKey = kp.private as org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters
        )
    }

    /**
     * Encapsulate: generate a fresh shared secret and encrypt it under [recipientPublicKey].
     * Returns Pair(ciphertext, sharedSecret).
     */
    fun kemEncapsulate(
        recipientPublicKey: org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters
    ): Pair<ByteArray, ByteArray> {
        val kem = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator(SecureRandom())
        val result = kem.generateEncapsulated(recipientPublicKey)
        return Pair(result.encapsulation, result.secret)
    }

    /**
     * Decapsulate: recover shared secret from [ciphertext] using [privateKey].
     */
    fun kemDecapsulate(
        privateKey: org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters,
        ciphertext: ByteArray
    ): ByteArray {
        val extractor = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor(privateKey)
        return extractor.extractSecret(ciphertext)
    }

    // -------------------------------------------------------------------------
    // Combined KDF  — HKDF-SHA256 over concatenated secrets
    // -------------------------------------------------------------------------

    /**
     * Derive a 32-byte session key from both component secrets plus a binding
     * transcript that includes both public keys and the KEM ciphertext.
     */
    fun deriveSessionKey(
        x25519Secret: ByteArray,
        kemSecret: ByteArray,
        transcript: ByteArray          // = x25519LocalPub || x25519RemotePub || kemCiphertext
    ): ByteArray {
        val ikm = x25519Secret + kemSecret
        return hkdfSha256(ikm = ikm, salt = transcript, info = "RNET-v1-session".toByteArray(), length = 32)
    }

    // -------------------------------------------------------------------------
    // HKDF (RFC 5869) — SHA-256 variant
    // -------------------------------------------------------------------------

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        // Extract
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        // Expand
        val output = mutableListOf<Byte>()
        var prev = ByteArray(0)
        var counter = 1
        while (output.size < length) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(prev)
            mac.update(info)
            mac.update(counter.toByte())
            prev = mac.doFinal()
            output.addAll(prev.toList())
            counter++
        }
        return output.take(length).toByteArray()
    }
}
