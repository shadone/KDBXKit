//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension InnerHeader {
    struct ChaCha20Key {
        let key: [UInt8]
        let nonce: [UInt8]

        init?(key: [UInt8], nonce: [UInt8]) {
            guard key.count == 32, nonce.count == 12 else { return nil }
            self.key = key
            self.nonce = nonce
        }

        init?(innerEncryptionKey: Data) {
            /// `K` should consist of 64 bytes.
            guard innerEncryptionKey.count == 64 else { return nil }

            /// Compute `H := SHA-512(K)`.
            let hash = innerEncryptionKey.sha512()

            /// The key for ChaCha20 is `H[0], ..., H[31]`
            key = Array(hash.subdata(in: 0..<32))

            /// and the nonce is `H[32], ..., H[43]`.
            nonce = Array(hash.subdata(in: 32..<44))
        }
    }

    var chaCha20Key: ChaCha20Key? {
        guard case .ChaCha20 = encryptionAlgorithm else { return nil }
        return .init(innerEncryptionKey: encryptionKey)
    }
}
