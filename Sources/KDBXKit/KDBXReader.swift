//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CommonCrypto
import CryptoKit
import Foundation
import SwiftGzip

/// Parser for the `.kdbx` file format.
///
/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.                           <<- parses
/// 2. SHA-256 hash of the header.       <<- validates
/// 3. HMAC-SHA-256 hash of the header.  <<- validates
/// 4. In HMAC-protected block stream:   <<- parses
///    a. Encrypted:                     <<- decrypts
///       i. Compressed (optional):      <<- decompresses
///          - Inner header.             <<- parses & returns binary content
///          - XML document.             <<- returns
/// ```
///
/// https://keepass.info/help/kb/kdbx.html
public struct KDBXReader: Sendable {
    public enum Error: Swift.Error {
        /// The provided key data (e.g. master password) does not match.
        ///
        /// This is triggered early in the parsing, when computing HMAC-SHA256 of the header and comparing it with the one
        /// stored in the file.
        case invalidUnlockData

        /// The provided KDBX file is not supported.
        case unsupported(reason: String)

        case corrupted(reason: String)
        case unexpectedEOF
    }

    let data: Data
    var pos: Data.Index

    /// The header of the `.kdbx` file.
    ///
    /// - note: This is for debug purposes, for accessing the value even if the parsing failed due to e.g. invalid master password.
    public private(set) var header: Header?

    /// The inner header of the `.kdbx` file.
    ///
    /// - note: This is for debug purposes, for accessing the value even if the parsing failed due to e.g. corrupted content.
    public private(set) var innerHeader: InnerHeader?

    /// The raw XML document but before decryption of the string content (i.e. no inner decryption applied)
    ///
    /// - note: This is for debug purposes, for accessing the value even if the parsing failed due to e.g. corrupted content.
    public private(set) var xmlDocument: String?

    /// The size of the each blocks of the HMAC-protected block stream.
    ///
    /// - note: This is for debug purposes.
    public private(set) var blockSizes: [Int32] = []

    public init(_ data: Data) {
        self.data = data
        pos = data.startIndex
    }

    // MARK: Read <token> helpers

    private mutating func readInt32() throws(Error) -> Int32 {
        try readData(length: 4).asInt32LE()! // safe to force unwrap as we guaranteed to read enough bytes
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

    // MARK: Public API

    public mutating func parse(unlockData: UnlockData?) throws(Error) -> KDBXContent {
        let header: Header
        let headerLength: Int

        // MARK: 1. Header

        do {
            var reader = HeaderReader(data: data)
            (header, headerLength) = try reader.parse()
            self.header = header
        } catch {
            switch error {
            case .invalidSignature:
                throw .corrupted(reason: "Invalid file signature")
            case let .unsupportedFormatVersion(major, minor):
                throw .unsupported(reason: "KDBX format version \(major).\(minor) is not supported")
            case let .unsupportedCompression(compression):
                throw .unsupported(reason: "The specified compression algorithm (\(compression)) is not supported")
            case let .unsupportedEncryption(uuid):
                throw .unsupported(reason: "The specified encryption algorithm (\(uuid.uuidString)) is not supported")
            case let .corrupted(reason):
                throw .corrupted(reason: "Header: \(reason)")
            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }

        // Move past the header to the next token
        pos = pos.advanced(by: headerLength)

        // MARK: 2. SHA-256 of the header

        // calculate SHA256 of the header
        let headerData = Data(data[..<headerLength])
        let headerSHA256 = headerData.sha256()

        print("### got header length", headerLength)
        print("### got header", header)

        let headerSHA256FromFile = try readData(length: 32)
        if headerSHA256 != headerSHA256FromFile {
            print("### header", header)
            print("### header sha256 (ours)", headerSHA256.hexString)
            print("### header sha256 (file)", headerSHA256FromFile.hexString)
            throw Error.corrupted(reason: "Invalid header SHA256 digest")
        }

        guard let unlockData else {
            // Shortcircuit early if the master password was not provided, maybe the intention
            // is to read the header only.
            throw .invalidUnlockData
        }

        // MARK: 3. HMAC-SHA256 of the header

        // calculate HMAC-SHA256 of the header
        let unlockKey = unlockData.computeUnlockKey(
            salt: header.masterSalt,
            kdfParameters: header.kdfParameters,
        )

        let headerKey = keyForHeader(masterSalt: header.masterSalt, unlockKey: unlockKey)

        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        let headerHMACSHA256FromFile = try readData(length: 32)
        if headerHMACSHA256 != headerHMACSHA256FromFile {
            print("### headerHMACSHA256 (ours)", headerHMACSHA256.hexString)
            print("### headerHMACSHA256 (file)", headerHMACSHA256FromFile.hexString)
            throw Error.invalidUnlockData
        }

        // MARK: 4. Parse HMAC-protected block stream

        var blockIndex: UInt64 = 0
        var payload = Data(capacity: data.count)
        while true {
            let hmacFromFile = try readData(length: 32)
            let size = try readInt32()
            let block = try readData(length: Int(size))

            if size != 0 {
                blockSizes.append(size)
            }

            // The HMAC-protected block stream is terminated by an output block for an empty
            // input block (i.e. M empty, s = 0).
            if size == 0 {
                assert(block.isEmpty)
                break
            }

            let blockKey = keyForBlock(
                at: blockIndex,
                masterSalt: header.masterSalt,
                unlockKey: unlockKey
            )

            var digest = HMAC<SHA256>(key: SymmetricKey(data: blockKey))
            digest.update(data: blockIndex.dataLE)
            digest.update(data: size.dataLE)
            digest.update(data: block)
            let hmac = Data(digest.finalize())

            if hmac != hmacFromFile {
                print("Block \(blockIndex) HMAC mismatch: ours \(hmac.hexString), file \(hmacFromFile.hexString)")
                break
            }

            payload.append(block)

            blockIndex += 1
        }

        // MARK: 4.a Decrypt payload

        // If the encryption algorithm needs a 256-bit key (such as AES-256 and ChaCha20),
        // the key is:
        // SHA-256(S ‖ T).
        // If the encryption algorithm needs a key smaller than 256 bits, the key consists of
        // the first bytes of SHA-256(S ‖ T).
        let mainDecryptKey = (header.masterSalt + unlockKey).sha256()

        switch header.encryptionAlgorithm {
        case .AES256CBC:
            payload = AES256CBC.decrypt(iv: header.encryptionNonce, cipherText: payload, mainDecryptKey)

        case .ChaCha20:
            fatalError("ChaCha20 is unsupported")
        }

        // MARK: 4.a.i Decompress payload if needed

        switch header.compressionAlgorithm {
        case .none:
            break

        case .gzip:
            do {
                let decompressor = GzipDecompressor()
                payload = try decompressor.unzip(data: payload)
            } catch {
                print("### Failed to decompress", error)
                throw Error.corrupted(reason: "failed to decompress")
            }
        }

        // MARK: 4.a.i.1 Parse Inner Header

        let innerHeader: InnerHeader
        let innerHeaderLength: Int
        do {
            var innerHeaderReader = InnerHeaderReader(data: payload)
            (innerHeader, innerHeaderLength) = try innerHeaderReader.parse()
            self.innerHeader = innerHeader
        } catch {
            switch error {
            case let .corrupted(reason):
                throw Error.corrupted(reason: "Inner header: \(reason)")
            case .unexpectedEOF:
                throw Error.unexpectedEOF
            }
        }

        // Remvove the inner header leaving only the XML document in the payload.
        payload.removeFirst(innerHeaderLength)

        // MARK: 4.a.i.2 XML Document

        // The remaining payload is the XML document
        guard let xmlDocument = String(data: payload, encoding: .utf8) else {
            throw Error.corrupted(reason: "Failed to parse the XML document as a utf8 string")
        }
        self.xmlDocument = xmlDocument

        let database: KDBX
        do {
            let xmlDocumentReader = XMLDocumentReader(xmlDocument: xmlDocument)
            database = try xmlDocumentReader.parse()
        } catch {
            switch error {
            case let .corrupted(reason):
                throw .corrupted(reason: "Database: \(reason)")
            }
        }

        return .init(database: database, header: header, innerHeader: innerHeader)
    }

    // MARK: Decryption helpers

    func keyForBlock(at index: UInt64, masterSalt: Data, unlockKey: Data) -> Data {
        // The key for the HMAC-SHA-256 hash of the i-th block (zero-based index, type UInt64)
        // of the HMAC-protected block stream is:
        // SHA-512(i ‖ SHA-512(S ‖ T ‖ 0x01)).
        (index.dataLE + (masterSalt + unlockKey + Data([0x01])).sha512()).sha512()
    }

    func keyForHeader(masterSalt: Data, unlockKey: Data) -> Data {
        // The key for the HMAC-SHA-256 hash of the header is:
        // SHA-512(0xFFFFFFFFFFFFFFFF ‖ SHA-512(S ‖ T ‖ 0x01)).
        let lastIndex: UInt64 = 0xFFFFFFFFFFFFFFFF
        return keyForBlock(at: lastIndex, masterSalt: masterSalt, unlockKey: unlockKey)
    }
}
