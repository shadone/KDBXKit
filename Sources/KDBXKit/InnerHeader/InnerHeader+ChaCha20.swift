//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension InnerHeader {
    private func makeCryptor() -> any Encryptable & Decryptable {
        switch encryptionAlgorithm {
        case .ChaCha20:
            /// `K` should consist of 64 bytes.
            guard encryptionKey.count == 64 else {
                fatalError("Invalid inner encryption (ChaCha20) key length: \(encryptionKey.count)")
            }

            /// Compute `H := SHA-512(K)`.
            let hash = encryptionKey.sha512()

            /// The key for ChaCha20 is `H[0], ..., H[31]`
            let key = hash.subdata(in: 0..<32)

            /// and the nonce is `H[32], ..., H[43]`.
            let nonce = hash.subdata(in: 32..<44)

            return try! ChaCha20(key: key, iv: nonce)

        case .Salsa20:
            /// `K` should consist of 32 bytes.
            guard encryptionKey.count == 32 else {
                fatalError("Invalid inner encryption (Salsa20) key length: \(encryptionKey.count)")
            }

            /// The key for Salsa20 is SHA-256(K)
            let key = encryptionKey.sha256()

            /// and the nonce is `0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A`
            let nonce = Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])

            return try! Salsa20(key: key, iv: nonce)
        }
    }

    func makeDecryptor() -> any Decryptable {
        makeCryptor()
    }

    func makeEncryptor() -> any Encryptable {
        makeCryptor()
    }
}
