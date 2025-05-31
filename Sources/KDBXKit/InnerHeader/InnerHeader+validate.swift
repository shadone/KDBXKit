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
                results.append(.error("Invalid encryption key length: \(encryptionKey.count). expected 64 bytes."))
            }

        case .Salsa20:
            fatalError()
        }

        for (index, binaryContent) in binaryContent.enumerated() {
            if binaryContent.data.isEmpty {
                results.append(.warning("Binary content at index \(index) is empty."))
            }
        }

        return results
    }
}
