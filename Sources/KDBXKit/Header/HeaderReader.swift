//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.                           <<- parses
/// 2. SHA-256 hash of the header.       <<- validates
/// 3. HMAC-SHA-256 hash of the header.  <<- validates
/// 4. In HMAC-protected block stream:
///    a. Encrypted:
///       i. Compressed (optional):
///          - Inner header.
///          - XML document.
/// ```
struct HeaderReader: Sendable {
    enum Error: Swift.Error {
        case invalidSignature
        case unsupportedFormatVersion(major: UInt16, minor: UInt16)
        case unsupportedCompression(UInt32)
        case unsupportedEncryption(UUID)

        case corrupted(reason: String)
        case unexpectedEOF
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

    private mutating func readUInt32() throws(Error) -> UInt32 {
        do { return try cursor.readUInt32LE() } catch { throw .unexpectedEOF }
    }

    private mutating func readData(length: Int) throws(Error) -> Data {
        do { return try cursor.readData(length: length) } catch { throw .unexpectedEOF }
    }

    // MARK: Public API

    mutating func parse() throws(Error) -> (header: Header, length: Int) {
        let signature1 = try readUInt32()
        let signature2 = try readUInt32()
        if signature1 != Header.signature1 || signature2 != Header.signature2 {
            throw Error.invalidSignature
        }

        let formatVersionValue = try readUInt32()
        let formatVersion = Header.FormatVersion(rawValue: formatVersionValue)
        // The 4.x slice of the canonical supported set — this reader only
        // handles major 4 (the 3.x framing has a separate reader). Derived
        // rather than literal so the supported-format rule lives in exactly
        // one place (`Header.FormatVersion.supported`).
        let supportedFormatVersions = Header.FormatVersion.supported.filter { $0.major == 4 }
        if !supportedFormatVersions.contains(formatVersion) {
            throw Error.unsupportedFormatVersion(major: formatVersion.major, minor: formatVersion.minor)
        }

        var encryptionAlgorithm: Header.EncryptionAlgorithm?
        var compressionAlgorithm: Header.CompressionAlgorithm?
        var masterSalt: Data?
        var encryptionNonce: Data?
        var allKdfParameters: VariantDictionary?
        var publicCustomData: VariantDictionary?

        var done = false
        while !done {
            // parse fields: <ID type (UInt8)> || <Length (Int32)> || <Value>
            let type = try readUInt8()
            let valueLength = try readUInt32()
            let valueData = try readData(length: Int(valueLength))

            guard let fieldType = HeaderFieldType(rawValue: type) else {
                KDBXLog.header.debug("Unknown field type: \(type)")
                continue
            }

            switch fieldType {
            case .endOfHeader:
                if valueData != HeaderFieldType.endOfHeaderValue {
                    throw Error.corrupted(reason: "Invalid end-of-header value. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                done = true

            case .compressionAlgorithm:
                guard let compressionRawValue = valueData.asUInt32LE() else {
                    throw Error.corrupted(reason: "Invalid compression algorithm. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                guard let compression = Header.CompressionAlgorithm(rawValue: compressionRawValue) else {
                    throw Error.unsupportedCompression(compressionRawValue)
                }
                compressionAlgorithm = compression

            case .encryptionAlgorithm:
                guard let uuidValue = UInt128(littleEndianData: valueData) else {
                    throw Error.corrupted(reason: "Encryption algorithm value is not a valid UUID. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                guard let algorithm = Header.EncryptionAlgorithm(rawValue: uuidValue) else {
                    throw Error.unsupportedEncryption(UUID(uint128: uuidValue))
                }
                encryptionAlgorithm = algorithm

            case .masterSalt:
                if valueData.count != 32 {
                    throw Error.corrupted(reason: "Invalid master salt length. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                masterSalt = valueData

            case .encryptionNonce:
                encryptionNonce = valueData

            case .kdfParameters:
                let reader = VariantDictionaryReader(data: valueData)
                do {
                    allKdfParameters = try reader.parse()
                } catch {
                    switch error {
                    case let .corrupted(reason):
                        throw Error.corrupted(reason: "Invalid KDF parameters: \(reason)")
                    case .unexpectedEOF:
                        throw Error.unexpectedEOF
                    case let .unsupportedFormatVersion(major, minor):
                        throw Error.corrupted(reason: "Unsupported KDF parameters format version: \(major).\(minor)")
                    }
                }

            case .publicCustomData:
                let reader = VariantDictionaryReader(data: valueData)
                do {
                    publicCustomData = try reader.parse()
                } catch {
                    switch error {
                    case let .corrupted(reason):
                        throw Error.corrupted(reason: "Invalid KDF parameters: \(reason)")
                    case .unexpectedEOF:
                        throw Error.unexpectedEOF
                    case let .unsupportedFormatVersion(major, minor):
                        throw Error.corrupted(reason: "Unsupported KDF parameters format version: \(major).\(minor)")
                    }
                }
            }
        }

        // Parsing done, validate parsed data

        guard let encryptionAlgorithm else {
            throw Error.corrupted(reason: "Missing encryption algorithm")
        }
        guard let encryptionNonce else {
            throw Error.corrupted(reason: "Missing encryption nonce")
        }
        switch encryptionAlgorithm {
        case .AES256CBC:
            guard encryptionNonce.count == 16 else {
                throw Error.corrupted(reason: "Invalid AES256 encryption nonce length. Length: \(encryptionNonce.count); bytes: \(encryptionNonce.hexString)")
            }

        case .ChaCha20:
            guard encryptionNonce.count == 12 else {
                throw Error.corrupted(reason: "Invalid ChaCha20 encryption nonce length. Length: \(encryptionNonce.count); bytes: \(encryptionNonce.hexString)")
            }
        }
        guard let masterSalt else {
            throw Error.corrupted(reason: "Missing master seed")
        }

        guard let allKdfParameters else {
            throw Error.corrupted(reason: "Missing KDF parameters")
        }

        guard let kdfParameters = KDFParameters(from: allKdfParameters) else {
            throw Error.corrupted(reason: "Failed to parse KDF parameters: \(allKdfParameters)")
        }

        // 🎉

        let header = Header(
            formatVersion: formatVersion,
            encryptionAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm ?? .none,
            masterSalt: masterSalt,
            encryptionNonce: encryptionNonce,
            kdfParameters: kdfParameters,
            publicCustomData: publicCustomData ?? [:]
        )

        return (header: header, length: cursor.position)
    }
}
