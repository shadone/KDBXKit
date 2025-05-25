//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CommonCrypto
import CryptoKit
import Foundation
import SwiftGzip

public struct KDBXReader: Sendable {
    enum Error: Swift.Error {
        case corrupted(reason: String)
        case unexpectedEOF
    }

    let data: Data
    var pos: Data.Index

    public private(set) var header: Header?
    public private(set) var innerHeader: InnerHeader?

    public private(set) var blockSizes: [Int32] = []

    public init(_ data: Data) {
        self.data = data
        pos = data.startIndex
    }

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

    public mutating func parse(unlockData: UnlockData) throws -> String {
        var reader = HeaderReader(data: data)
        let (header, headerLength) = try reader.parse()
        self.header = header

        pos = pos.advanced(by: headerLength)

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

        // calculate HMAC-SHA256 of the header
        let unlockKey = computeUnlockKey(
            salt: header.masterSalt,
            kdfParameters: header.kdfParameters,
            unlockData: unlockData
        )

        let headerKey = keyForHeader(masterSalt: header.masterSalt, unlockKey: unlockKey)

        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        let headerHMACSHA256FromFile = try readData(length: 32)
        if headerHMACSHA256 != headerHMACSHA256FromFile {
            print("### headerHMACSHA256 (ours)", headerHMACSHA256.hexString)
            print("### headerHMACSHA256 (file)", headerHMACSHA256FromFile.hexString)
            throw Error.corrupted(reason: "Invalid header HMAC-SHA256 digest")
        }

        // Parse HMAC-protected block stream
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

        // Decrypt payload

        // If the encryption algorithm needs a 256-bit key (such as AES-256 and ChaCha20),
        // the key is:
        // SHA-256(S ‖ T).
        // If the encryption algorithm needs a key smaller than 256 bits, the key consists of
        // the first bytes of SHA-256(S ‖ T).
        let mainDecryptKey = (header.masterSalt + unlockKey).sha256()

        switch header.encryptionAlgorithm {
        case .AES256:
            let decrypted = AES256CBC.decrypt(iv: header.encryptionNonce, cipherText: payload, mainDecryptKey)
            payload = decrypted

        case .ChaCha20:
            fatalError("ChaCha20 is unsupported")
        }

        // Decompress payload if needed

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

        // Parse Inner Header

        do {
            var innerHeaderReader = InnerHeaderReader(data: payload)
            let (innerHeader, innerHeaderLength) = try innerHeaderReader.parse()
            self.innerHeader = innerHeader
            payload.removeFirst(innerHeaderLength)
        } catch {
            switch error {
            case let .corrupted(reason):
                throw Error.corrupted(reason: "Inner header: \(reason)")
            case .unexpectedEOF:
                throw Error.unexpectedEOF
            }
        }

        // The remaining payload is the XML document

        guard let xmlDocument = String(data: payload, encoding: .utf8) else {
            throw Error.corrupted(reason: "Failed to parse the XML document as a utf8 string")
        }

        return xmlDocument
    }

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

    func makeKeyData(
        unlockData: UnlockData
    ) -> Data {
        // Let R be the SHA-256 hash of the concatenation of the components of the master key
        // that the user has provided (each optional, in the following order):
        var r = SHA256()

        // 1. SHA-256 hash of the master password (encoded using UTF-8).
        if let masterPassword = unlockData.masterPassword {
            let utf8 = masterPassword.data(using: .utf8)! // Swift.String -> utf8 cannot fail
            r.update(data: utf8.sha256())
        }

        // 2. Key stored in a key file.
        if let keyFile = unlockData.keyFile {
            r.update(data: keyFile)
        }

        // 3. Key provided by a key provider plugin.
        // 4. Key protected using the Windows user account (DPAPI).

        return Data(r.finalize())
    }

    func computeUnlockKey(
        salt _: Data,
        kdfParameters: KDFParameters,
        unlockData: UnlockData
    ) -> Data {
        let keydata = makeKeyData(unlockData: unlockData)

        // Let T be the result of transforming R using a key derivation function. The function and
        // parameters for it are stored in the header.
        switch kdfParameters {
        case .aes:
            fatalError("unimplemented")

        case .argon2d(let params, additional: _):
            return argon2d(password: keydata, params: params)

        case .argon2id(let params, additional: _):
            return argon2id(password: keydata, params: params)

        case .unknown:
            fatalError("Internal error: unknown KDF")
        }
    }
}
