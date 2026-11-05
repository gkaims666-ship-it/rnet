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
 * ML-KEM-768 is provided via Bouncy Castle (bcprov-jdk18on). X25519 is provided via
 * the Android/JVM built-in XDH provider. The final 32-byte session key feeds the
 * AES-256-GCM AEAD layer in SessionCipher.
 *
 * Key generation timeline (initiator side):
 *   1. generateX25519KeyPair()          → ephemeral Diffie-Hellman keypair
 *   2. generateKemKeyPair()             → ML-KEM-768 keypair
 *   3. Send   [ x25519.public | kem.public ] to responder
 *   4. Receive [ x25519.public | ciphertext ] from responder
 *   5. deriveSharedSecret(...)          → 32-byte session key
 *
 * Responder side:
 *   1. Receive [ x25519.public | kem.public ]
 *   2. generateX25519KeyPair()
 *   3. encapsulate(kem.public)          → (ciphertext, kem_shared)
 *   4. Send   [ x25519.public | ciphertext ]
 *   5. deriveSharedSecret(...)          → same 32-byte session key
 */
object HybridKeyExchange {

    private const val TAG = "HybridKEX"

    private val bcProvider by lazy {
        org.bouncycastle.jce.provider.BouncyCastleProvider()
    }

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
    // ML-KEM-768 (via Bouncy Castle JCA — KYBER768)
    // -------------------------------------------------------------------------

    fun generateKemKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("KYBER768", bcProvider)
        kpg.initialize(
            org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec.kyber768,
            SecureRandom()
        )
        return kpg.generateKeyPair()
    }

    /**
     * Encapsulate: generate a fresh shared secret and encrypt it under [recipientPublicKey].
     * Returns Pair(ciphertext, sharedSecret).
     */
    fun kemEncapsulate(recipientPublicKey: PublicKey): Pair<ByteArray, ByteArray> {
        val bcPub = recipientPublicKey as org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey
        val kyberPub = bcPub.keyParams
        val kem = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator(SecureRandom())
        val kemResult = kem.generateEncapsulated(kyberPub)
        return Pair(kemResult.encapsulation, kemResult.secret)
    }

    /**
     * Decapsulate: recover shared secret from [ciphertext] using [privateKey].
     */
    fun kemDecapsulate(privateKey: java.security.PrivateKey, ciphertext: ByteArray): ByteArray {
        val bcPriv = privateKey as org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey
        val extractor = org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor(bcPriv.keyParams)
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
