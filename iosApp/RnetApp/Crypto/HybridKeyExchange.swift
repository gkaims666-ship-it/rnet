import Foundation
import CryptoKit

/// HybridKeyExchange — ML-KEM-768 (CRYSTALS-Kyber) + X25519 hybrid key encapsulation.
///
/// Architecture:
///   shared_secret = KDF( X25519_shared || KEM_shared, transcript )
///
/// On iOS 18+ the full hybrid (ML-KEM-768 + X25519) is used via Apple CryptoKit.
/// On iOS 16–17 only the X25519 leg is used; the KEM leg produces a deterministic
/// placeholder so the HKDF and session-key derivation remain functionally complete.
/// The session key is forwarded to SessionCipher (AES-256-GCM).
struct HybridKeyExchange {

    // MARK: - X25519

    typealias X25519PrivateKey = Curve25519.KeyAgreement.PrivateKey
    typealias X25519PublicKey  = Curve25519.KeyAgreement.PublicKey

    static func generateX25519KeyPair() -> X25519PrivateKey {
        X25519PrivateKey()
    }

    static func x25519SharedSecret(
        localPrivate: X25519PrivateKey,
        remotePub: X25519PublicKey
    ) throws -> Data {
        let sharedSecret = try localPrivate.sharedSecretFromKeyAgreement(with: remotePub)
        // Extract raw bytes via HKDF expand (CryptoKit SharedSecret → Data)
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("X25519-leg".utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    // MARK: - ML-KEM-768 (iOS 18+)

    /// Encapsulate using ML-KEM-768 when available; returns (ciphertext, sharedSecret).
    /// On older OS versions returns a placeholder derived from the transcript.
    static func kemEncapsulate(
        recipientPublicKeyData: Data,
        transcript: Data
    ) throws -> (ciphertext: Data, sharedSecret: Data) {
        if #available(iOS 18.0, macOS 15.0, *) {
            let pubKey = try MLKEMPublicKey(rawRepresentation: recipientPublicKeyData, variant: .P768)
            let (sharedSecret, ciphertext) = try pubKey.encapsulate()
            let secretData = sharedSecret.withUnsafeBytes { Data($0) }
            return (ciphertext.rawRepresentation, secretData)
        } else {
            // iOS 16–17 fallback: derive a deterministic placeholder from transcript
            // so HKDF still produces a valid session key (X25519 provides the security).
            let placeholder = HMAC<SHA256>.authenticationCode(
                for: transcript,
                using: SymmetricKey(data: SHA256.hash(data: transcript))
            )
            let placeholderData = Data(placeholder)
            return (Data("kem-placeholder-ct".utf8), placeholderData)
        }
    }

    /// Decapsulate ML-KEM-768 ciphertext with private key.
    static func kemDecapsulate(
        privateKeyData: Data,
        ciphertext: Data,
        transcript: Data
    ) throws -> Data {
        if #available(iOS 18.0, macOS 15.0, *) {
            let privKey = try MLKEMPrivateKey(rawRepresentation: privateKeyData, variant: .P768)
            let sharedSecret = try privKey.decapsulate(MLKEMCiphertext(rawRepresentation: ciphertext, variant: .P768))
            return sharedSecret.withUnsafeBytes { Data($0) }
        } else {
            let placeholder = HMAC<SHA256>.authenticationCode(
                for: transcript,
                using: SymmetricKey(data: SHA256.hash(data: transcript))
            )
            return Data(placeholder)
        }
    }

    /// Generate ML-KEM key pair. Returns (publicKeyData, privateKeyData).
    static func generateKEMKeyPair() throws -> (publicKey: Data, privateKey: Data) {
        if #available(iOS 18.0, macOS 15.0, *) {
            let privKey = MLKEMPrivateKey(variant: .P768)
            return (privKey.publicKey.rawRepresentation, privKey.rawRepresentation)
        } else {
            // iOS 16–17: generate random placeholder bytes (not used for crypto on these OS)
            var pubBytes = Data(count: 1184)  // ML-KEM-768 public key size
            var privBytes = Data(count: 2400) // ML-KEM-768 private key size
            pubBytes.withUnsafeMutableBytes  { _ = SecRandomCopyBytes(kSecRandomDefault, 1184, $0.baseAddress!) }
            privBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 2400, $0.baseAddress!) }
            return (pubBytes, privBytes)
        }
    }

    // MARK: - Combined KDF

    /// Derive a 32-byte session key from both component secrets plus a binding transcript.
    /// transcript = x25519LocalPub || x25519RemotePub || kemCiphertext
    static func deriveSessionKey(
        x25519Secret: Data,
        kemSecret: Data,
        transcript: Data
    ) -> Data {
        let ikm = x25519Secret + kemSecret
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: transcript,
            info: Data("RNET-v1-session".utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }
}
