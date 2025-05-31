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
    /// The master password was given but doesn't match the password used for encryption
    case invalidUnlockData(KDBXReader)
}

func read(from filepath: String, unlockData: UnlockData?) throws(ReadError) -> ReadResult {
    let data: Data
    do {
        data = try Data(contentsOf: URL(filePath: filepath))
    } catch {
        throw .canNotReadFile
    }

    var kdbxReader = KDBXReader(data)

    do {
        let content = try kdbxReader.parse(unlockData: unlockData)
        return .success(content, kdbxReader)
    } catch {
        switch error {
        case .invalidUnlockData:
            if unlockData != nil {
                // the user provided master password but it doesn't match
                return .invalidUnlockData(kdbxReader)
            } else {
                // the user did not provide master password, so expected failure
                return .invalidUnlockData(kdbxReader)
            }

        case let .unsupported(reason):
            throw .unsupported("The specified KDBX file is not supported: \(reason)")

        case let .corrupted(reason):
            throw .corrupted("Failed to parse KDBX file: \(reason)")

        case .unexpectedEOF:
            throw .corrupted("Failed to parse KDBX file: unexpected end of file")
        }
    }
}
