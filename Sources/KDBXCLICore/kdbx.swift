//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

enum ReadError: Error, CustomStringConvertible {
    case unsupported(String)

    case corrupted(String)

    case canNotReadFile

    var description: String {
        switch self {
        case let .unsupported(message):
            return "The given file is not supported: \(message)"
        case let .corrupted(message):
            return "The given file is corrupted: \(message)"
        case .canNotReadFile:
            return "Can not read the file"
        }
    }
}

enum ReadResult {
    case success(KDBXContent, KDBXReader)
    /// No unlock data was provided. The header is still inspectable.
    case noCredentials(KDBXReader)
    /// Unlock data was provided but doesn't match.
    case wrongCredentials(KDBXReader)
}

func read(
    from filepath: String,
    unlockData: UnlockData?,
    retainsXMLForDiagnostics: Bool = false
) throws(ReadError) -> ReadResult {
    let data: Data
    do {
        data = try Data(contentsOf: URL(filePath: filepath))
    } catch {
        throw .canNotReadFile
    }

    var kdbxReader = KDBXReader(data)

    do {
        let content = try kdbxReader.parse(
            unlockData: unlockData,
            retainsXMLForDiagnostics: retainsXMLForDiagnostics
        )
        return .success(content, kdbxReader)
    } catch {
        switch error {
        case .unlockDataRequired:
            return .noCredentials(kdbxReader)
        case .wrongCredentials:
            return .wrongCredentials(kdbxReader)

        case let .unsupportedFormatVersion(major, minor):
            throw .unsupported("Format version \(major).\(minor) is not supported")
        case let .unsupportedEncryption(uuid):
            throw .unsupported("Encryption algorithm \(uuid.uuidString) is not supported")
        case let .unsupportedCompression(code):
            throw .unsupported("Compression algorithm \(code) is not supported")
        case let .unsupportedKDF(uuid):
            throw .unsupported("KDF \(uuid.uuidString) is not supported")

        case .invalidFileSignature:
            throw .corrupted("Not a KDBX file (invalid signature)")
        case let .corruptedHeader(reason):
            throw .corrupted("Corrupted header: \(reason)")
        case let .kdfParametersOutOfRange(reason):
            throw .corrupted("KDF parameters exceed policy: \(reason)")
        case .corruptedHeaderDigest:
            throw .corrupted("Corrupted header digest")
        case let .corruptedHMAC(reason):
            throw .corrupted("Corrupted HMAC: \(reason)")
        case let .corruptedInnerHeader(reason):
            throw .corrupted("Corrupted inner header: \(reason)")
        case let .corruptedXML(reason):
            throw .corrupted("Corrupted XML: \(reason)")
        case let .decompressedPayloadTooLarge(limit):
            throw .corrupted("Decompressed payload exceeds limit (\(limit) bytes)")
        case .unexpectedEOF:
            throw .corrupted("Unexpected end of file")
        }
    }
}
