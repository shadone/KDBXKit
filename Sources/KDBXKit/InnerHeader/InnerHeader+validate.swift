//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension InnerHeader {
    enum ValidationError: Error {
        case invalidEncryptionKeyLength(reason: String)
    }

    func validate() throws(ValidationError) {
        switch encryptionAlgorithm {
        case .Salsa20:
            guard encryptionKey.count == 32 else {
                throw .invalidEncryptionKeyLength(reason: "Salsa20 key should be 32 bytes long")
            }

        case .ChaCha20:
            guard encryptionKey.count == 64 else {
                throw .invalidEncryptionKeyLength(reason: "ChaCha20 key should be 64 bytes long")
            }
        }
    }
}
