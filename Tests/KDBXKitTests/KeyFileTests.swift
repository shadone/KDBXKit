//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Validates that the `UnlockData(masterPassword:, keyFile:)` and
/// `UnlockData(keyFile:)` initializers actually produce different unlock
/// keys (so they round-trip distinct ciphertexts), and that mismatched
/// credentials are rejected.
@Suite("Key-file unlock")
struct KeyFileTests {

    @Test("Password + key file round-trips")
    func passwordAndKeyFile() throws {
        let content = KDBXContent.makeEmpty(databaseName: "WithKeyFile", kdf: .fast)
        let keyFile = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let unlock = UnlockData(masterPassword: "pw", keyFile: keyFile)

        let bytes = try writeToMemory(content, unlockData: unlock)
        let reopened = try KDBXReader.parse(bytes, unlockData: unlock)
        #expect(reopened.database.meta.databaseName == "WithKeyFile")
    }

    @Test("Key file alone (no password) round-trips")
    func keyFileOnly() throws {
        let content = KDBXContent.makeEmpty(databaseName: "KeyOnly", kdf: .fast)
        let keyFile = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let unlock = UnlockData(keyFile: keyFile)

        let bytes = try writeToMemory(content, unlockData: unlock)
        let reopened = try KDBXReader.parse(bytes, unlockData: unlock)
        #expect(reopened.database.meta.databaseName == "KeyOnly")
    }

    @Test("Right password but wrong key file is rejected")
    func wrongKeyFile() throws {
        let content = KDBXContent.makeEmpty(databaseName: "X", kdf: .fast)
        let keyA = Data(repeating: 0xAA, count: 64)
        let keyB = Data(repeating: 0xBB, count: 64)

        let bytes = try writeToMemory(content, unlockData: .init(masterPassword: "pw", keyFile: keyA))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(bytes, unlockData: .init(masterPassword: "pw", keyFile: keyB))
        }
    }

    @Test("Password-only file rejects password+keyfile unlock")
    func componentsMustMatch() throws {
        let content = KDBXContent.makeEmpty(databaseName: "X", kdf: .fast)
        let keyFile = Data(repeating: 0xAA, count: 64)
        let bytes = try writeToMemory(content, unlockData: .init(masterPassword: "pw"))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(bytes, unlockData: .init(masterPassword: "pw", keyFile: keyFile))
        }
    }

    private func writeToMemory(_ content: KDBXContent, unlockData: UnlockData) throws -> Data {
        let stream = OutputStream(toMemory: ())
        stream.open()
        try KDBXWriter(to: stream).write(content, unlockData: unlockData)
        let bytes = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        stream.close()
        return bytes
    }
}
