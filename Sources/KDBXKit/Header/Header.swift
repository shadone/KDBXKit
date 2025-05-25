//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public struct Header: Sendable {
    public struct FormatVersion: CustomStringConvertible, Equatable, Sendable {
        public let major: UInt16
        public let minor: UInt16

        public var description: String {
            "\(major).\(minor)"
        }

        public static let v4_0: FormatVersion = .init(major: 4, minor: 0)
        public static let v4_1: FormatVersion = .init(major: 4, minor: 1)
    }

    /// File format version.
    ///
    /// - An application can load the file if it supports the major version.
    /// - If the minor version of the file is greater than the one that the application supports, the application may try to load the file,
    ///   ignoring any unknown items. Certain data may be lost in this case, thus showing a confirmation/warning is recommended.
    public let formatVersion: FormatVersion

    public enum EncryptionAlgorithm: Sendable {
        /// AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding).
        case AES256CBC

        /// ChaCha20 (RFC 8439).
        case ChaCha20
    }

    public let encryptionAlgorithm: EncryptionAlgorithm

    public enum CompressionAlgorithm: CustomStringConvertible, Sendable {
        case gzip

        public var description: String {
            switch self {
            case .gzip: return "gzip"
            }
        }
    }

    /// Whether compression is applied.
    public let compressionAlgorithm: CompressionAlgorithm?

    /// Master salt/seed (⟳)
    ///
    /// Salt/seed for [computing the keys](https://keepass.info/help/kb/kdbx.html#keys).
    ///
    /// - note: Must be regenerated each time KDBX file is saved!
    ///
    /// Value type: `Byte[32]`
    public let masterSalt: Data

    /// Encryption IV/nonce (⟳)
    ///
    /// Initialization vector or nonce for the encryption algorithm. 16 bytes for AES-256, 12 bytes for ChaCha20.
    ///
    /// - note: Must be regenerated each time KDBX file is saved!
    ///
    /// Value type: `Byte[]`
    public let encryptionNonce: Data

    /// Parameters for the key derivation function (KDF).
    public let kdfParameters: KDFParameters

    /// Custom data of plugins/ports.
    ///
    /// The name of an item should be unique, e.g. `"PluginName_ItemName"`.
    ///
    /// In this header field, only data that must be readable without decryption should be stored (e.g. data by a key provider plugin
    /// required for decryption). All other custom data should be stored in the encrypted XML document
    /// (elements `//Meta/CustomData`, `//Group/CustomData` and `//Entry/CustomData`).
    ///
    /// Value type: [`Variant dictionary`](https://keepass.info/help/kb/kdbx.html#vardict).
    public let publicCustomData: VariantDictionary
}
