//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

struct HeaderReader: Sendable {
    enum Error: Swift.Error {
        case invalidSignature
        case unsupportedFormatVersion(major: UInt16, minor: UInt16)
        case unsupportedCompression(UInt32)
        case unsupportedEncryption(UUID)

        case corrupted(reason: String)
        case unexpectedEOF
    }

    let data: Data
    var pos: Data.Index

    init(data: Data) {
        self.data = data
        pos = data.startIndex
    }

    private mutating func readUInt8() throws(Error) -> UInt8 {
        if pos + 1 > data.count {
            throw Error.unexpectedEOF
        }

        let b = data[pos]

        pos = pos.advanced(by: 1)

        return b
    }

    private mutating func readUInt32() throws(Error) -> UInt32 {
        try readData(length: 4).asUInt32LE()! // safe to force unwrap as we guaranteed to read enough bytes
    }

    private mutating func readData(length: Int) throws(Error) -> Data {
        let start = pos
        let end = pos.advanced(by: length)

        if end > data.endIndex {
            throw Error.unexpectedEOF
        }

        let subdata = data.subdata(in: start..<end)

        pos = end

        return subdata
    }

    mutating func parse() throws(Error) -> (header: Header, length: Int) {
        let signature1 = try readUInt32()
        let signature2 = try readUInt32()
        if signature1 != 0x9AA2D903 || signature2 != 0xB54BFB67 {
            throw Error.invalidSignature
        }

        let formatVersionValue = try readUInt32()
        let majorVersion = UInt16(formatVersionValue >> 16)
        let minorVersion = UInt16(formatVersionValue & 0xFFFF) >> 8
        let formatVersion = Header.FormatVersion(major: majorVersion, minor: minorVersion)
        let supportedFormatVersions: [Header.FormatVersion] = [
            .v4_0,
            .v4_1,
        ]
        if !supportedFormatVersions.contains(formatVersion) {
            throw Error.unsupportedFormatVersion(major: majorVersion, minor: minorVersion)
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

            print("Got header field: type=\(type), length=\(valueLength); value=\(valueData.hexString)")

            guard let fieldType = HeaderFieldType(rawValue: type) else {
                print("Unknown field type: \(type)")
                continue
            }

            switch fieldType {
            case .endOfHeader:
                if valueData != Data([0x0D, 0x0A, 0x0D, 0x0A]) {
                    throw Error.corrupted(reason: "Invalid end-of-header value. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                done = true

            case .compressionAlgorithm:
                if let compression = valueData.asUInt32LE() {
                    if compression == 0 {
                        compressionAlgorithm = .none
                    } else if compression == 1 {
                        compressionAlgorithm = .gzip
                    } else {
                        print("Invalid compression algorithm: \(compression)")
                        throw Error.unsupportedCompression(compression)
                    }
                } else {
                    print("Invalid compression algorithm value: \(valueData)")
                    throw Error.corrupted(reason: "Invalid compression algorithm. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }

            case .encryptionAlgorithm:
                /// - 31C1F2E6BF714350BE5805216AFC5AFF: AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding).
                let aes256 = UUID(uuid: (0xFF, 0x5A, 0xFC, 0x6A, 0x21, 0x05, 0x58, 0xBE, 0x50, 0x43, 0x71, 0xBF, 0xE6, 0xF2, 0xC1, 0x31))
                /// - D6038A2B8B6F4CB5A524339A31DBB59A: ChaCha20 (RFC 8439).
                let chacha20 = UUID(uuid: (0x9A, 0xB5, 0xDB, 0x31, 0x9A, 0x33, 0x24, 0xA5, 0xB5, 0x4C, 0x6F, 0x8B, 0x2B, 0x8A, 0x03, 0xD6))

                if let uuid = valueData.asUUIDLE() {
                    if uuid == aes256 {
                        encryptionAlgorithm = .AES256
                    } else if uuid == chacha20 {
                        encryptionAlgorithm = .ChaCha20
                    } else {
                        throw Error.unsupportedEncryption(uuid)
                    }
                } else {
                    throw Error.corrupted(reason: "Encryption algorithm value is not a valid UUID. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }

            case .masterSalt:
                if valueData.count != 32 {
                    throw Error.corrupted(reason: "Invalid master salt length. Length: \(valueData.count); bytes: \(valueData.hexString)")
                }
                masterSalt = valueData

            case .encryptionNonce:
                encryptionNonce = valueData

            case .kdfParameters:
                print("Parsing KDF parameters...")
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
                print("Parsing Public Custom Data...")
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
        case .AES256:
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
            compressionAlgorithm: compressionAlgorithm,
            masterSalt: masterSalt,
            encryptionNonce: encryptionNonce,
            kdfParameters: kdfParameters,
            publicCustomData: publicCustomData ?? [:]
        )

        return (header: header, length: pos)
    }
}
