//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension Header {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        switch encryptionAlgorithm {
        case .ChaCha20:
            if encryptionNonce.count != 12 {
                results.append(.error("Invalid ChaCha20 encryption nonce length: \(encryptionNonce.count), expected 12 bytes."))
            }

        case .AES256CBC:
            if encryptionNonce.count != 16 {
                results.append(.error("Invalid AES256CBC encryption nonce length: \(encryptionNonce.count), expected 16 bytes."))
            }
        }

        if masterSalt.count != 32 {
            results.append(.warning("Master salt is too short: \(masterSalt.count), expected 32 bytes."))
        }

        results += kdfParameters.validate()

        return results
    }
}
