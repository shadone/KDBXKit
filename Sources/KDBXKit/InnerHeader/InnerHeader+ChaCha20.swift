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
                fatalError("Invalid inner encryption key length: \(encryptionKey.count)")
            }

            /// Compute `H := SHA-512(K)`.
            let hash = encryptionKey.sha512()

            /// The key for ChaCha20 is `H[0], ..., H[31]`
            let key = hash.subdata(in: 0..<32)

            /// and the nonce is `H[32], ..., H[43]`.
            let nonce = hash.subdata(in: 32..<44)

            return try! ChaCha20(key: key, iv: nonce)

        case .Salsa20:
            fatalError("Salsa20 is not implemented yet")
        }
    }

    func makeDecryptor() -> any Decryptable {
        makeCryptor()
    }

    func makeEncryptor() -> any Encryptable {
        makeCryptor()
    }
}
