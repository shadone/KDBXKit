//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

enum ReadError: Error {
    case unsupported(String)

    case corrupted(String)
}

enum ReadResult {
    case success(Database, KDBXReader)
    /// The master password was given but doesn't match the password used for encryption
    case invalidUnlockData(KDBXReader)
}

func read(from filepath: String, unlockData: UnlockData?) throws(ReadError) -> ReadResult {
    let data = try! Data(contentsOf: URL(filePath: filepath))

    var kdbxReader = KDBXReader(data)

    do {
        let database = try kdbxReader.parse(unlockData: unlockData)
        return .success(database, kdbxReader)
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
