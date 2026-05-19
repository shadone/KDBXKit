//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public struct Header: Sendable, Equatable {
    static let signature1: UInt32 = 0x9AA2D903
    static let signature2: UInt32 = 0xB54BFB67

    public struct FormatVersion: CustomStringConvertible, Equatable, Sendable {
        public let major: UInt16
        public let minor: UInt16

        public var description: String {
            "\(major).\(minor)"
        }

        /// The value is in **little endian**.
        var rawValue: UInt32 {
            (UInt32(major) << 16) | UInt32(minor)
        }

        init(major: UInt16, minor: UInt16) {
            self.major = major
            self.minor = minor
        }

        /// - parameter rawValue: the value should be in **little endian**
        init(rawValue: UInt32) {
            // The high word is the major version
            major = UInt16(rawValue >> 16)
            // The low word is the minor version.
            minor = UInt16(rawValue & 0xFFFF)
        }

        /// KDBX 3.1 (KeePass 2.20–2.34, KeePassXC default).
        ///
        /// KDBXKit opens 3.1 files; on save they are migrated to ``v4_1``.
        /// The on-disk layout differs from 4.x in several places —
        /// `UInt16` header field lengths, an outer-header `StreamStartBytes`
        /// integrity scheme (no SHA-256 / HMAC trailer), a plain hashed
        /// block stream instead of the HMAC-protected one, binaries
        /// inlined in XML rather than in an inner header, and Salsa20 as
        /// the inner stream cipher. See `Header3xReader` for the parser.
        ///
        /// KDBX 3.0 (KeePass 2.10–2.19) is **not** supported: its default
        /// inner stream cipher was the ArcFour-variant we reject, and the
        /// format predates the inner-random-stream header field entirely.
        /// 3.0 files are rejected with
        /// ``KDBXReader/Error/unsupportedFormatVersion(major:minor:)``.
        public static let v3_1: FormatVersion = .init(major: 3, minor: 1)

        public static let v4_0: FormatVersion = .init(major: 4, minor: 0)
        public static let v4_1: FormatVersion = .init(major: 4, minor: 1)

        /// Whether the format predates KDBX 4 (i.e. uses the 3.x on-disk
        /// shape: `UInt16` header field lengths, `StreamStartBytes`,
        /// hashed block stream, inline XML binaries, ISO-8601 dates).
        public var isLegacy3x: Bool {
            major == 3
        }
    }

    /// File format version.
    ///
    /// - An application can load the file if it supports the major version.
    /// - If the minor version of the file is greater than the one that the application supports, the application may try to load the file,
    ///   ignoring any unknown items. Certain data may be lost in this case, thus showing a confirmation/warning is recommended.
    public let formatVersion: FormatVersion

    public enum EncryptionAlgorithm: UInt128, Sendable, Equatable {
        /// AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding).
        case AES256CBC = 0xFF5AFC6A210558BE504371BFE6F2C131

        /// ChaCha20 (RFC 8439).
        case ChaCha20 = 0x9AB5DB319A3324A5B54C6F8B2B8A03D6
    }

    public let encryptionAlgorithm: EncryptionAlgorithm

    public enum CompressionAlgorithm: UInt32, CustomStringConvertible, Sendable, Equatable {
        case none = 0
        case gzip = 1

        public var description: String {
            switch self {
            case .none: return "none"
            case .gzip: return "gzip"
            }
        }
    }

    /// Whether compression is applied.
    public let compressionAlgorithm: CompressionAlgorithm

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
    public var publicCustomData: VariantDictionary

    public init(
        formatVersion: FormatVersion,
        encryptionAlgorithm: EncryptionAlgorithm,
        compressionAlgorithm: CompressionAlgorithm,
        masterSalt: Data,
        encryptionNonce: Data,
        kdfParameters: KDFParameters,
        publicCustomData: VariantDictionary
    ) {
        self.formatVersion = formatVersion
        self.encryptionAlgorithm = encryptionAlgorithm
        self.compressionAlgorithm = compressionAlgorithm
        self.masterSalt = masterSalt
        self.encryptionNonce = encryptionNonce
        self.kdfParameters = kdfParameters
        self.publicCustomData = publicCustomData
    }
}
