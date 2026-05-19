//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension InnerHeader {
    /// Inner-stream cipher construction failure surface. The KDBX 4 spec
    /// fixes the key length per algorithm (64 bytes for ChaCha20, 32 for
    /// Salsa20); a real file never carries the wrong size because the
    /// inner-header parser rejects mismatches. Defense-in-depth, in case
    /// a future refactor weakens that check — we throw rather than crash
    /// the host process. Untyped `throws` because `SecureBytes.withUnsafeBytes`
    /// is declared `rethrows` over an untyped closure and won't propagate
    /// a typed error out unchanged; callers re-wrap as
    /// `KDBXReader.Error.corruptedInnerHeader` / equivalent.
    enum CryptorError: Swift.Error, Equatable, Sendable {
        case invalidKeyLength(algorithm: EncryptionAlgorithm, expected: Int, got: Int)
    }

    private func makeCryptor() throws -> any Encryptable & Decryptable {
        try encryptionKey.withUnsafeBytes { keyPtr -> any Encryptable & Decryptable in
            var rawKey = Data(keyPtr.bindMemory(to: UInt8.self))
            defer {
                rawKey.withUnsafeMutableBytes { ptr in
                    _ = ptr.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }

            switch encryptionAlgorithm {
            case .ChaCha20:
                /// `K` should consist of 64 bytes.
                guard rawKey.count == 64 else {
                    throw CryptorError.invalidKeyLength(algorithm: .ChaCha20, expected: 64, got: rawKey.count)
                }

                /// Compute `H := SHA-512(K)`.
                let hash = rawKey.sha512()

                /// The key for ChaCha20 is `H[0], ..., H[31]`
                let key = hash.subdata(in: 0..<32)

                /// and the nonce is `H[32], ..., H[43]`.
                let nonce = hash.subdata(in: 32..<44)

                // ChaCha20 init only fails on key/iv length mismatch. With
                // the upstream length check passing, SHA-512 → 32-byte key
                // + 12-byte nonce makes this slice infallible.
                return try! ChaCha20(key: key, iv: nonce)

            case .Salsa20:
                /// `K` should consist of 32 bytes.
                guard rawKey.count == 32 else {
                    throw CryptorError.invalidKeyLength(algorithm: .Salsa20, expected: 32, got: rawKey.count)
                }

                /// The key for Salsa20 is SHA-256(K)
                let key = rawKey.sha256()

                /// and the nonce is `0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A`
                let nonce = Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])

                // Salsa20 init only fails on key/iv length mismatch. Same
                // reasoning as above — both sides are length-fixed here.
                return try! Salsa20(key: key, iv: nonce)
            }
        }
    }

    func makeDecryptor() throws -> any Decryptable {
        try makeCryptor()
    }

    func makeEncryptor() throws -> any Encryptable {
        try makeCryptor()
    }

    /// Produce a `KeystreamSource` carrying the inner-cipher key and
    /// nonce. Used by the reader to emit `.lazyInnerCipher`
    /// `ProtectedString.Value`s — same key derivation as
    /// `makeCryptor()`, but value-typed and Sendable so it can be
    /// embedded in entries without keeping a stateful cipher alive.
    func makeKeystreamSource() throws -> KeystreamSource {
        try encryptionKey.withUnsafeBytes { keyPtr -> KeystreamSource in
            var rawKey = Data(keyPtr.bindMemory(to: UInt8.self))
            defer {
                rawKey.withUnsafeMutableBytes { ptr in
                    _ = ptr.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }

            switch encryptionAlgorithm {
            case .ChaCha20:
                // K is 64 bytes. The inner cipher derives:
                //   H := SHA-512(K)
                //   key   = H[0..32]
                //   nonce = H[32..44]
                guard rawKey.count == 64 else {
                    throw CryptorError.invalidKeyLength(algorithm: .ChaCha20, expected: 64, got: rawKey.count)
                }
                let hash = rawKey.sha512()
                let key = hash.subdata(in: 0..<32)
                let nonce = hash.subdata(in: 32..<44)
                return KeystreamSource(
                    algorithm: .chacha20,
                    key: SecureBytes(key),
                    nonce: nonce
                )

            case .Salsa20:
                // K is 32 bytes; key = SHA-256(K). Nonce is a fixed
                // constant from the KDBX spec.
                guard rawKey.count == 32 else {
                    throw CryptorError.invalidKeyLength(algorithm: .Salsa20, expected: 32, got: rawKey.count)
                }
                let key = rawKey.sha256()
                let nonce = Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])
                return KeystreamSource(
                    algorithm: .salsa20,
                    key: SecureBytes(key),
                    nonce: nonce
                )
            }
        }
    }
}
