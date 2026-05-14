//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoKit
import CryptoSwift
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
public struct KDBXWriter {
    public enum Error: Swift.Error {
        case unknown(reason: String)
        /// When writing to a fixed length stream, there is no place to write.
        case unexpectedEOF
    }

    let outputStream: OutputStream

    public init(to outputStream: OutputStream) {
        self.outputStream = outputStream
    }

    private func write(_ data: Data) throws(Error) {
        do {
            try outputStream.write(data: data)
        } catch {
            switch error {
            case let .streamError(error):
                let description = error?.localizedDescription ?? "nil"
                throw .unknown(reason: "Write failed: \(description)")

            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }
    }

    private func serialize(_ header: Header) throws(Error) -> Data {
        let headerOutputStream = OutputStream(toMemory: ())
        headerOutputStream.open()

        do {
            try HeaderWriter(to: headerOutputStream).write(header)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .unknown(reason: "Failed to write header: \(reason)")
            }
        }

        guard let data = headerOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Failed to get output stream data for Header")
        }

        return data
    }

    private func serialize(_ innerHeader: InnerHeader) throws(Error) -> Data {
        let innerHeaderOutputStream = OutputStream(toMemory: ())
        innerHeaderOutputStream.open()

        do {
            try InnerHeaderWriter(to: innerHeaderOutputStream).write(innerHeader)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .unknown(reason: "Failed to write inner header: \(reason)")
            }
        }

        guard let data = innerHeaderOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Failed to get output stream data for Inner Header")
        }

        return data
    }

    private func serialize(_ database: KDBX, encryptor: any Encryptable) throws(Error) -> Data {
        let xmlDocumentOutputStream = OutputStream(toMemory: ())
        xmlDocumentOutputStream.open()

        do {
            try XMLDocumentWriter(to: xmlDocumentOutputStream, encryptor: encryptor).write(database)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .unknown(reason: "Failed to write header: \(reason)")
            }
        }

        guard let data = xmlDocumentOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Failed to get output stream data for Header")
        }

        return data
    }

    private func writeHMACProtectedBlock(
        index blockIndex: UInt64,
        data: Data,
        masterSalt: Data,
        unlockKey: Data
    ) throws(Error) {
        let blockKey = HMACProtectedBlockStream.keyForBlock(
            at: UInt64(blockIndex),
            masterSalt: masterSalt,
            unlockKey: unlockKey
        )

        let blockSize = Int32(data.count)

        var digest = HMAC<SHA256>(key: SymmetricKey(data: blockKey))
        digest.update(data: UInt64(blockIndex).dataLE)
        digest.update(data: blockSize.dataLE)
        digest.update(data: data)
        let hmac = Data(digest.finalize())

        try write(hmac)
        try write(blockSize.dataLE)
        try write(data)
    }

    public func write(_ content: KDBXContent, unlockData: UnlockData) throws(Error) {
        guard outputStream.streamStatus == .open else {
            throw .unknown(reason: "Stream is not ready for writing")
        }

        // MARK: 1. Header

        let headerData = try serialize(content.header)
        try write(headerData)

        // MARK: 2. SHA-256 of the header

        let headerSHA256 = headerData.sha256()
        try write(headerSHA256)

        // MARK: 3. HMAC-SHA256 of the header

        let unlockKey: Data
        do {
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: content.header.kdfParameters)
        } catch {
            switch error {
            case let .unsupportedKDF(uuid):
                throw .unknown(reason: "Unsupported KDF: \(uuid.uuidString)")
            }
        }

        let headerKey = HMACProtectedBlockStream.keyForHeader(
            masterSalt: content.header.masterSalt,
            unlockKey: unlockKey
        )

        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        try write(headerHMACSHA256)

        // MARK: 4. Prepare for HMAC-protected block stream

        var payload = Data()

        // MARK: 4.a Serialize Inner Header

        payload += try serialize(content.innerHeader)

        // MARK: 4.b Serialize XML Document

        payload += try serialize(content.database, encryptor: content.innerHeader.makeEncryptor())

        // MARK: 4.c Compress payload if needed

        switch content.header.compressionAlgorithm {
        case .none:
            break

        case .gzip:
            do {
                payload = try GzipCompressor().zip(data: payload)
            } catch {
                throw Error.unknown(reason: "failed to compress: \(error)")
            }
        }

        // MARK: 4.d Encrypt payload

        let mainContentKey = MainKey.make(masterSalt: content.header.masterSalt, unlockKey: unlockKey)

        switch content.header.encryptionAlgorithm {
        case .AES256CBC:
            do {
                let AES256CBC = try AES(
                    key: Array(mainContentKey),
                    blockMode: CBC(iv: Array(content.header.encryptionNonce)),
                    padding: .pkcs7
                )
                payload = try Data(AES256CBC.encrypt(Array(payload)))
            } catch {
                throw .unknown(reason: "Failed to encrypt main payload: \(error)")
            }

        case .ChaCha20:
            guard let chaCha20 = try? ChaCha20(key: mainContentKey, iv: content.header.encryptionNonce) else {
                throw .unknown(reason: "Failed to initialize ChaCha20, invalid decryption key or nonce")
            }
            payload = Data(chaCha20.decrypt(payload))
        }

        // MARK: 4.e Write HMAC-protected block stream

        // A very small block size results in a large KDBX file (due to the additional HMACs and
        // size values).
        // A very large block size requires a lot of process memory.
        //
        // So, except in special cases (e.g. a small block at the end of the file), neither the
        // minimum nor the maximum is a good choice for the block size; a good size is in the
        // "middle".
        //
        // When saving a KDBX file, KeePass currently uses 1048576 (i.e. 1 MB) as size for every
        // input block except the last one (which may be smaller).
        let blockSize = 1_048_576

        var blockIndex: UInt64 = 0
        for start in stride(from: 0, to: payload.count, by: blockSize) {
            let end = min(start + blockSize, payload.endIndex)
            let block = payload.subdata(in: start..<end)

            try writeHMACProtectedBlock(
                index: blockIndex,
                data: block,
                masterSalt: content.header.masterSalt,
                unlockKey: unlockKey
            )

            blockIndex += 1
        }

        // The HMAC-protected block stream is terminated by an output block for an empty input block
        // (i.e. M empty, s = 0).
        try writeHMACProtectedBlock(
            index: blockIndex,
            data: Data(),
            masterSalt: content.header.masterSalt,
            unlockKey: unlockKey
        )
    }
}
