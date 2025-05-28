//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

/// https://keepass.info/help/kb/kdbx.html#iheader
enum InnerHeaderFieldType: UInt8, Sendable {
    /// Indicates the end of the header.
    ///
    /// Must be present exactly once, as the last header field.
    ///
    /// The value should be empty.
    case endOfHeader = 0

    /// 2 = Salsa20, 3 = ChaCha20 (default, recommended). See 'Inner Encryption'.
    ///
    /// Value type: `Int32`
    case encryptionAlgorithm = 1

    /// See [Inner Encryption](https://keepass.info/help/kb/kdbx.html#ienc).
    case encryptionKey = 2

    /// The value is f ‖ C, where f is a flags byte and C is the content of a binary (attachment).
    /// The flag 0x01 indicates that the binary content should be protected in the process memory. A binary content is
    /// referenced in the XML document by its index in the inner header (the first binary content has index 0, the second one
    /// has index 1, etc.).
    case binaryContent = 3
}
