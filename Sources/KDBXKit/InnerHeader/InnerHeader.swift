//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The inner header of a `.kdbx` file — vault metadata that lives
/// *inside* the encrypted block stream rather than in the outer
/// envelope.
///
/// Two things go here: the inner-stream cipher's key (used to
/// per-field XOR-encrypt protected strings in the XML, on top of
/// the outer cipher) and the deduplicated binary attachment pool.
/// Surfaced as ``KDBXContent/innerHeader``.
///
/// Inner-stream encryption is what makes "protected in memory"
/// meaningful: passwords land in the parsed XML as ciphertext, and
/// the reader only decrypts them when a caller asks. See
/// ``EncryptionAlgorithm-swift.enum`` and
/// <https://keepass.info/help/kb/kdbx.html#ienc>.
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
    public enum EncryptionAlgorithm: Int32, Sendable, Equatable {
        /// Salsa20.
        ///
        /// `K` should consist of 32 bytes. The key for Salsa20 is `SHA-256(K)`, and the nonce is `0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A`.
        ///
        /// Where `K` is the inner encryption key stored in the inner header.
        case Salsa20 = 2

        /// ChaCha20 (default, recommended)
        ///
        /// `K` should consist of 64 bytes. Compute `H := SHA-512(K)`. The key for ChaCha20 is `H[0], ..., H[31]`,
        /// and the nonce is `H[32], ..., H[43]`.
        ///
        /// Where `K` is the inner encryption key stored in the inner header.
        case ChaCha20 = 3
    }

    /// The algorithm used for encrypting protected strings in the XML document.
    public var encryptionAlgorithm: EncryptionAlgorithm

    /// The encryption key that was used for encrypting protected strings in the XML document. See ``EncryptionAlgorithm-swift.enum``
    ///
    /// For ChaCha20, the key is 64 bytes.
    /// For Salsa20, the key is 32 bytes.
    ///
    /// Held as `SecureBytes` (page-locked, zero-on-deinit) — this key
    /// encrypts every password in the unlocked vault; a process-memory dump
    /// of just this 32/64-byte value is enough to decrypt every protected
    /// string in the file.
    public var encryptionKey: SecureBytes

    /// A single attachment payload in the binary pool.
    ///
    /// KDBX 4 stores attachments here once, deduplicated by content;
    /// each ``KDBX/Entry/binaries`` entry references a pool slot by
    /// index via ``KDBX/ProtectedBinary/Value/ref(_:)``. Two
    /// byte-identical attachments on different entries share one
    /// `BinaryContent`.
    public struct BinaryContent: Sendable, Equatable {
        /// Whether the payload should be held in protected memory
        /// while resident — i.e. encrypted under the inner-stream
        /// cipher and decrypted only on demand. Mirrors the
        /// `protected` flag a referencing
        /// ``KDBX/ProtectedBinary/Value/inline(_:protected:)`` would
        /// have carried.
        public var shouldBeProtected: Bool

        /// Raw bytes of the attachment.
        public var data: Data

        public init(shouldBeProtected: Bool, data: Data) {
            self.shouldBeProtected = shouldBeProtected
            self.data = data
        }
    }

    /// The deduplicated binary pool. Each entry's
    /// ``KDBX/ProtectedBinary/Value/ref(_:)`` carries an index into
    /// this array — slot 0, 1, 2 … in declaration order.
    public var binaryContent: [BinaryContent]

    public init(
        encryptionAlgorithm: EncryptionAlgorithm,
        encryptionKey: SecureBytes,
        binaryContent: [BinaryContent]
    ) {
        self.encryptionAlgorithm = encryptionAlgorithm
        self.encryptionKey = encryptionKey
        self.binaryContent = binaryContent
    }

    /// Convenience for callers that have a `Data` in hand (e.g. parsers).
    public init(
        encryptionAlgorithm: EncryptionAlgorithm,
        encryptionKey: Data,
        binaryContent: [BinaryContent]
    ) {
        self.init(
            encryptionAlgorithm: encryptionAlgorithm,
            encryptionKey: SecureBytes(encryptionKey),
            binaryContent: binaryContent
        )
    }
}
