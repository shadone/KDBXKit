//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Parser for the KDBX 3.x file header.
///
/// Overview of a KDBX 3.x file:
///
/// ```
///                              This type:
/// 1. Signature + version       <<- parses
/// 2. Header fields (TLV)       <<- parses
/// 3. AES-CBC encrypted body:
///    a. StreamStartBytes (32)  <<- caller verifies after decrypt
///    b. HashedBlockStream:
///       i. Gzip-compressed (optional):
///          - XML document       (with inline <Meta><Binaries> pool)
/// ```
///
/// Compared to ``HeaderReader`` (the 4.x parser):
///
/// - Field lengths are encoded as `UInt16` instead of `UInt32`.
/// - There is no SHA-256 / HMAC-SHA-256 trailer; integrity rests on the
///   `StreamStartBytes` value being recovered after decryption.
/// - KDF parameters live in dedicated fields (`TransformSeed`,
///   `TransformRounds`) rather than a `VariantDictionary`. AES-KDF is the
///   only supported KDF in 3.x.
/// - The inner-stream cipher key + ID live in the outer header — in 4.x
///   they moved into the inner header.
///
/// The reader emits the same ``Header`` struct that 4.x produces, by
/// synthesizing a `KDFParameters.aes(...)` value from the dedicated
/// `TransformSeed` / `TransformRounds` fields. The 3.x-only payload-side
/// state (`StreamStartBytes`, `ProtectedStreamKey`, `InnerRandomStreamID`)
/// is returned alongside the `Header` via ``PayloadKeys``.
struct Header3xReader: Sendable {
    enum Error: Swift.Error {
        case invalidSignature
        case unsupportedFormatVersion(major: UInt16, minor: UInt16)
        case unsupportedCompression(UInt32)
        case unsupportedEncryption(UUID)
        case unsupportedInnerRandomStream(UInt32)

        case corrupted(reason: String)
        case unexpectedEOF
    }

    /// 3.x-only outer-header state needed by the payload pipeline.
    ///
    /// Not part of ``Header`` itself: those fields don't exist in the 4.x
    /// outer header, and synthesizing slots for them on `Header` would
    /// leak the legacy shape into every 4.x code path.
    struct PayloadKeys: Sendable, Equatable {
        /// 32 bytes that must appear as the first 32 plaintext bytes after
        /// AES-CBC decrypting the body. A mismatch indicates a wrong key.
        let streamStartBytes: Data

        /// 32-byte key for the inner stream cipher (Salsa20). Migrated
        /// into the synthesized ``InnerHeader.encryptionKey`` so the rest
        /// of the codebase consumes it through the same channel as 4.x.
        let protectedStreamKey: SecureBytes

        /// Selected inner-stream cipher. Currently only ``salsa20`` is
        /// supported; ``arcFour`` (KDBX 3.0) is rejected upstream.
        let innerRandomStreamID: InnerRandomStreamID
    }

    /// Identifiers for the inner-stream cipher as written in 3.x file
    /// headers (see ``InnerHeader.EncryptionAlgorithm`` for the analogous
    /// 4.x set, which shares the wire values for ``salsa20`` and
    /// ``chaCha20``).
    enum InnerRandomStreamID: UInt32, Sendable, Equatable {
        case none = 0
        /// ArcFour-variant. KDBX 3.0 legacy, never the default; we reject it.
        case arcFour = 1
        /// Salsa20. The KDBX 3.1 default.
        case salsa20 = 2
        /// ChaCha20. KDBX 4.x default; valid in a 3.x header but unusual.
        case chaCha20 = 3
    }

    var cursor: ByteCursor

    init(data: Data) {
        cursor = ByteCursor(data)
    }

    // MARK: Read <token> helpers

    //
    // Bounds-checking lives in `ByteCursor`; these adapters only re-wrap its
    // `unexpectedEOF` into this reader's `Error`.

    private mutating func readUInt8() throws(Error) -> UInt8 {
        do { return try cursor.readUInt8() } catch { throw .unexpectedEOF }
    }

    private mutating func readUInt16LE() throws(Error) -> UInt16 {
        do { return try cursor.readUInt16LE() } catch { throw .unexpectedEOF }
    }

    private mutating func readUInt32LE() throws(Error) -> UInt32 {
        do { return try cursor.readUInt32LE() } catch { throw .unexpectedEOF }
    }

    private mutating func readData(length: Int) throws(Error) -> Data {
        do { return try cursor.readData(length: length) } catch { throw .unexpectedEOF }
    }

    // MARK: Public API

    mutating func parse() throws(Error) -> (header: Header, payload: PayloadKeys, length: Int) {
        let signature1 = try readUInt32LE()
        let signature2 = try readUInt32LE()
        if signature1 != Header.signature1 || signature2 != Header.signature2 {
            throw .invalidSignature
        }

        let formatVersionValue = try readUInt32LE()
        let formatVersion = Header.FormatVersion(rawValue: formatVersionValue)
        // KDBX 3.1 is the only pre-4 version we support. 3.0 (KeePass
        // 2.10–2.19) is rejected here rather than later in the field
        // walk — 3.0's default inner stream cipher was the ArcFour
        // variant we'd otherwise reject downstream with a
        // .corrupted("Unsupported inner random stream ID") that's less
        // informative than an upfront version-level rejection.
        //
        // The 3.x slice of the canonical supported set (currently just
        // 3.1), derived rather than literal so the supported-format rule
        // lives in exactly one place (`Header.FormatVersion.supported`).
        let supportedFormatVersions = Header.FormatVersion.supported.filter { $0.major == 3 }
        if !supportedFormatVersions.contains(formatVersion) {
            throw .unsupportedFormatVersion(major: formatVersion.major, minor: formatVersion.minor)
        }

        var encryptionAlgorithm: Header.EncryptionAlgorithm?
        var compressionAlgorithm: Header.CompressionAlgorithm?
        var masterSeed: Data?
        var transformSeed: Data?
        var transformRounds: UInt64?
        var encryptionIV: Data?
        var protectedStreamKey: Data?
        var streamStartBytes: Data?
        var innerRandomStreamID: InnerRandomStreamID?

        var done = false
        while !done {
            // <ID type (UInt8)> || <Length (UInt16)> || <Value>
            let type = try readUInt8()
            let valueLength = try readUInt16LE()
            let valueData = try readData(length: Int(valueLength))

            guard let fieldType = HeaderFieldType3x(rawValue: type) else {
                KDBXLog.header.debug("Unknown 3.x field type: \(type)")
                continue
            }

            switch fieldType {
            case .endOfHeader:
                if valueData != HeaderFieldType3x.endOfHeaderValue {
                    throw .corrupted(reason: "Invalid end-of-header value. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                done = true

            case .comment:
                // Spec-allowed but unused by any modern writer; ignore.
                continue

            case .cipherID:
                guard let uuidValue = UInt128(littleEndianData: valueData) else {
                    throw .corrupted(reason: "Cipher ID is not a valid UUID. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                guard let algorithm = Header.EncryptionAlgorithm(rawValue: uuidValue) else {
                    throw .unsupportedEncryption(UUID(uint128: uuidValue))
                }
                encryptionAlgorithm = algorithm

            case .compressionFlags:
                guard let compressionRawValue = valueData.asUInt32LE() else {
                    throw .corrupted(reason: "Invalid compression flags. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                guard let compression = Header.CompressionAlgorithm(rawValue: compressionRawValue) else {
                    throw .unsupportedCompression(compressionRawValue)
                }
                compressionAlgorithm = compression

            case .masterSeed:
                if valueData.count != 32 {
                    throw .corrupted(reason: "Invalid master seed length. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                masterSeed = valueData

            case .transformSeed:
                if valueData.count != 32 {
                    throw .corrupted(reason: "Invalid transform seed length. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                transformSeed = valueData

            case .transformRounds:
                guard let rounds = valueData.asUInt64LE() else {
                    throw .corrupted(reason: "Invalid transform rounds. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                transformRounds = rounds

            case .encryptionIV:
                encryptionIV = valueData

            case .protectedStreamKey:
                if valueData.count != 32 {
                    throw .corrupted(reason: "Invalid protected stream key length. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                protectedStreamKey = valueData

            case .streamStartBytes:
                if valueData.count != 32 {
                    throw .corrupted(reason: "Invalid stream start bytes length. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                streamStartBytes = valueData

            case .innerRandomStreamID:
                guard let rawValue = valueData.asUInt32LE() else {
                    throw .corrupted(reason: "Invalid inner random stream ID. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                guard let id = InnerRandomStreamID(rawValue: rawValue) else {
                    throw .unsupportedInnerRandomStream(rawValue)
                }
                innerRandomStreamID = id
            }
        }

        // Required fields
        guard let encryptionAlgorithm else {
            throw .corrupted(reason: "Missing cipher ID")
        }
        // 3.x permits only AES-256-CBC. ChaCha20 was introduced in 4.0; a 3.x
        // header advertising it would be malformed.
        if encryptionAlgorithm != .AES256CBC {
            throw .unsupportedEncryption(UUID(uint128: encryptionAlgorithm.rawValue))
        }
        guard let encryptionIV else {
            throw .corrupted(reason: "Missing encryption IV")
        }
        if encryptionIV.count != 16 {
            throw .corrupted(reason: "Invalid AES-CBC IV length. Length: \(encryptionIV.count); bytes: \(encryptionIV.hexString)")
        }
        guard let masterSeed else {
            throw .corrupted(reason: "Missing master seed")
        }
        guard let transformSeed else {
            throw .corrupted(reason: "Missing transform seed")
        }
        guard let transformRounds else {
            throw .corrupted(reason: "Missing transform rounds")
        }
        guard let protectedStreamKey else {
            throw .corrupted(reason: "Missing protected stream key")
        }
        guard let streamStartBytes else {
            throw .corrupted(reason: "Missing stream start bytes")
        }
        guard let innerRandomStreamID else {
            throw .corrupted(reason: "Missing inner random stream ID")
        }
        // ArcFour is the KDBX 3.0 legacy default and was never the KDBX 3.1
        // default — we don't carry it forward; flag the rare file that uses
        // it rather than emit a broken keystream.
        if innerRandomStreamID == .arcFour {
            throw .unsupportedInnerRandomStream(InnerRandomStreamID.arcFour.rawValue)
        }
        if innerRandomStreamID == .none {
            throw .corrupted(reason: "Inner random stream ID is 'none'; protected fields would be unrecoverable")
        }

        let header = Header(
            formatVersion: formatVersion,
            encryptionAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm ?? .none,
            masterSalt: masterSeed,
            encryptionNonce: encryptionIV,
            // Synthesize KDFParameters.aes so unlock-key derivation flows
            // through the same path as a 4.x AES-KDF file.
            kdfParameters: .aes(.init(salt: transformSeed, rounds: transformRounds), additional: [:]),
            publicCustomData: [:]
        )

        let payload = PayloadKeys(
            streamStartBytes: streamStartBytes,
            protectedStreamKey: SecureBytes(protectedStreamKey),
            innerRandomStreamID: innerRandomStreamID
        )

        return (header: header, payload: payload, length: cursor.position)
    }
}
