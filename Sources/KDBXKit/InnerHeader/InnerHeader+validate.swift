//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension InnerHeader {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        switch encryptionAlgorithm {
        case .ChaCha20:
            if encryptionKey.count != 64 {
                results.append(.error("Invalid ChaCha20 encryption key length: \(encryptionKey.count). expected 64 bytes."))
            }

        case .Salsa20:
            if encryptionKey.count != 32 {
                results.append(.error("Invalid Salsa20 encryption key length: \(encryptionKey.count). expected 64 bytes."))
            }
        }

        for (index, binaryContent) in binaryContent.enumerated() {
            if binaryContent.data.isEmpty {
                results.append(.warning("Binary content at index \(index) is empty."))
            }
        }

        return results
    }
}
