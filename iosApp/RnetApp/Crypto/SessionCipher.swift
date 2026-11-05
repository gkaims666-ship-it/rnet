import Foundation
import CryptoKit

/// AES-256-GCM session cipher — iOS counterpart to the Android SessionCipher.kt
/// Wire format: [12 B nonce | ciphertext + 16 B tag]
final class SessionCipher {

    private let key: SymmetricKey

    /// - Parameter keyBytes: 32-byte session key derived via HKDF (see HybridKeyExchange.swift)
    init(keyBytes: Data) throws {
        guard keyBytes.count == 32 else {
            throw CipherError.invalidKeyLength(keyBytes.count)
        }
        key = SymmetricKey(data: keyBytes)
    }

    // MARK: - Encrypt

    /// Returns [12 B nonce | ciphertext+tag]
    func encrypt(_ plaintext: Data, aad: Data = Data()) throws -> Data {
        let nonce = try AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        var result = Data(nonce)              // 12 bytes
        result.append(sealed.ciphertext)
        result.append(sealed.tag)            // 16 bytes
        return result
    }

    // MARK: - Decrypt

    /// Expects [12 B nonce | ciphertext+tag]
    func decrypt(_ payload: Data, aad: Data = Data()) throws -> Data {
        guard payload.count > 28 else { throw CipherError.payloadTooShort }
        let nonceData = payload.prefix(12)
        let cipherAndTag = payload.dropFirst(12)
        let tagOffset = cipherAndTag.count - 16
        guard tagOffset > 0 else { throw CipherError.payloadTooShort }
        let ciphertext = cipherAndTag.prefix(tagOffset)
        let tag = cipherAndTag.suffix(16)

        let nonce = try AES.GCM.Nonce(data: nonceData)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }

    // MARK: - Errors

    enum CipherError: Error {
        case invalidKeyLength(Int)
        case payloadTooShort
    }
}
