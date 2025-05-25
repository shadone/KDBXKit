//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public struct InnerHeader: Sendable {
    public enum EncryptionAlgorithm: Sendable {
        case Salsa20
        case ChaCha20
    }

    public let encryptionAlgorithm: EncryptionAlgorithm

    public let encryptionKey: Data

    public struct BinaryContent: Sendable {
        /// The flag indicates that the binary content should be protected in the process memory.
        public let shouldBeProtected: Bool
        public let data: Data
    }

    /// A binary content is referenced in the XML document by its index in the inner header (the first binary content has
    /// index 0, the second one has index 1, etc.).
    public let binaryContent: [BinaryContent]
}
