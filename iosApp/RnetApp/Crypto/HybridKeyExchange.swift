import Foundation
import CryptoKit

/// iOS counterpart to HybridKeyExchange.kt.
///
/// Implements the same X25519 + ML-KEM-768 hybrid protocol using Apple CryptoKit
/// for the X25519 leg.  ML-KEM is not yet in CryptoKit as of iOS 17; we use a
/// pure-Swift reference implementation bundled as a local package (MLKEMSwift).
/// When Apple ships CryptoKit.MLKEM768 (expected iOS 18+), swap the import.
///
/// Session key derivation (matches Android exactly):
///   transcript    = x25519_pub_a || x25519_pub_b || kem_ciphertext
///   session_key   = HKDF-SHA256(IKM  = x25519_shared || kem_shared,
///                                salt = transcript,
///                                info = "RNET-v1-session",
///                                L    = 32)
final class HybridKeyExchange {

    // MARK: - X25519 keypair

    struct X25519KeyPair {
        let privateKey: Curve25519.KeyAgreement.PrivateKey
        var publicKeyBytes: Data { privateKey.publicKey.rawRepresentation }
    }

    static func generateX25519KeyPair() -> X25519KeyPair {
        X25519KeyPair(privateKey: Curve25519.KeyAgreement.PrivateKey())
    }

    static func x25519SharedSecret(
        localPrivate: Curve25519.KeyAgreement.PrivateKey,
        remotePubBytes: Data
    ) throws -> Data {
        let remotePub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePubBytes)
        let shared = try localPrivate.sharedSecretFromKeyAgreement(with: remotePub)
        // Extract raw 32-byte shared secret
        return shared.withUnsafeBytes { Data($0) }
    }

    // MARK: - Session key derivation

    static func deriveSessionKey(
        x25519SharedSecret: Data,
        kemSharedSecret: Data,
        localX25519Pub: Data,
        remoteX25519Pub: Data,
        kemCiphertext: Data
    ) throws -> Data {
        var ikm = Data()
        ikm.append(x25519SharedSecret)
        ikm.append(kemSharedSecret)

        var transcript = Data()
        transcript.append(localX25519Pub)
        transcript.append(remoteX25519Pub)
        transcript.append(kemCiphertext)

        let info = Data("RNET-v1-session".utf8)

        // HKDF-SHA256 via CryptoKit
        let hkdf = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: transcript,
            info: info,
            outputByteCount: 32
        )
        return hkdf.withUnsafeBytes { Data($0) }
    }
}
