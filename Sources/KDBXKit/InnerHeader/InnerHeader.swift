//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public struct InnerHeader: Sendable, Equatable {
    /// Most XML parsers work with regular strings, which may be difficult to erase from the process memory.
    /// So, if sensitive data would be stored unencryptedly in the XML document, a process memory protection could not be realized
    /// properly.
    ///
    /// Solution: all data that should be protected in the process memory is stored in encrypted form in the XML document.
    ///
    /// For this, the encryption algorithm and key stored in the inner header are used. The encryption algorithm is a stream cipher and
    /// its state is not reset for each data to be protected (thus the order in which the data to be protected appears is important).
    ///
    /// For example, if there is an entry A with a password consisting of 23 UTF-8 bytes and an entry B with a password consisting of
    /// 19 UTF-8 bytes (and A appears before B), then the password of A is encrypted using the first 23 output bytes of the stream
    /// cipher and the password of B is encrypted using the next (not first) 19 output bytes of the stream cipher.
    ///
    /// When loading a KDBX file, an application typically decrypts the protected data and immediately protects it using a method
    /// suitable for the current operating system (e.g. DPAPI on Windows).
    ///
    /// https://keepass.info/help/kb/kdbx.html#ienc
    public enum EncryptionAlgorithm: Sendable, Equatable {
        /// Salsa20.
        ///
        /// `K` should consist of 32 bytes. The key for Salsa20 is `SHA-256(K)`, and the nonce is `0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A`.
        ///
        /// Where `K` is the inner encryption key stored in the inner header.
        case Salsa20

        /// ChaCha20 (default, recommended)
        ///
        /// `K` should consist of 64 bytes. Compute `H := SHA-512(K)`. The key for ChaCha20 is `H[0], ..., H[31]`,
        /// and the nonce is `H[32], ..., H[43]`.
        ///
        /// Where `K` is the inner encryption key stored in the inner header.
        case ChaCha20
    }

    /// The algorithm used for encrypting protected strings in the XML document.
    public let encryptionAlgorithm: EncryptionAlgorithm

    /// The encryption key that was used for encrypting protected strings in the XML document. See ``EncryptionAlgorithm-swift.enum``
    public let encryptionKey: Data

    public struct BinaryContent: Sendable, Equatable {
        /// The flag indicates that the binary content should be protected in the process memory.
        public let shouldBeProtected: Bool
        public let data: Data
    }

    /// A binary content is referenced in the XML document by its index in the inner header (the first binary content has
    /// index 0, the second one has index 1, etc.).
    public let binaryContent: [BinaryContent]
}
