//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The outer file header of a `.kdbx` file — the cleartext envelope
/// that wraps the encrypted vault.
///
/// Carries everything a reader needs *before* unlocking: the format
/// version, the outer cipher choice, the compression mode, the
/// master salt + encryption nonce (regenerated on every save), the
/// KDF parameters, and any public custom data plugins want
/// accessible without credentials. Surfaced as
/// ``KDBXContent/header``; available without credentials via
/// ``KDBXReader/parseHeader(_:)``.
///
/// On save the writer regenerates ``masterSalt`` and
/// ``encryptionNonce`` from a CSPRNG unless explicitly opted out
/// via `regenerateSalts: false` (only meaningful for golden-file
/// testing).
public struct Header: Sendable, Equatable {
    static let signature1: UInt32 = 0x9AA2D903
    static let signature2: UInt32 = 0xB54BFB67

    /// The KDBX format version a file claims on disk —
    /// `major.minor`, e.g. `4.1`.
    ///
    /// KDBXKit reads 3.1, 4.0, and 4.1; writes 4.1. Use
    /// ``isLegacy3x`` to branch on "is this a pre-4 file" without
    /// re-implementing the version comparison.
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

        /// The exact set of on-disk format versions KDBXKit can read.
        ///
        /// Single source of truth for "can we open this format?". The
        /// route-specific readers derive their accept lists from this
        /// (`HeaderReader` takes the `major == 4` slice, `Header3xReader`
        /// the `major == 3` slice), and ``KDBXReader/validateSupportedFormat(_:)``
        /// checks membership for header-only callers (peek paths) that
        /// skip the KDF. When KDBX 5 lands — or a 4.x subvariant is
        /// dropped — this is the one place to edit.
        public static let supported: [FormatVersion] = [.v3_1, .v4_0, .v4_1]

        /// Whether KDBXKit can read this format. Equivalent to membership
        /// in ``supported``.
        public var isSupported: Bool {
            Self.supported.contains(self)
        }

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

    /// Outer cipher used to encrypt the vault's block stream.
    /// Identified on disk by a 16-byte UUID.
    public enum EncryptionAlgorithm: UInt128, Sendable, Equatable {
        /// AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding).
        case AES256CBC = 0xFF5AFC6A210558BE504371BFE6F2C131

        /// ChaCha20 (RFC 8439).
        case ChaCha20 = 0x9AB5DB319A3324A5B54C6F8B2B8A03D6
    }

    /// The outer cipher used to encrypt the encrypted block stream.
    public let encryptionAlgorithm: EncryptionAlgorithm

    /// Compression applied to the cleartext payload before
    /// encryption. KDBX 4 default is ``gzip``; ``none`` is rare in
    /// the wild.
    public enum CompressionAlgorithm: UInt32, CustomStringConvertible, Sendable, Equatable {
        /// No compression — cleartext payload is encrypted as-is.
        case none = 0

        /// gzip-compressed cleartext payload (with the inner header
        /// and XML inside the gzip stream).
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
