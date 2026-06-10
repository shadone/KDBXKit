//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXCLICore
@testable import KDBXKit

@Suite("VaultWriting")
struct VaultWritingTests {
    @Test("writeAtomically produces a file that re-parses with the same credentials")
    func roundTrip() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("v.kdbx")

        let content = KDBXContent.makeEmpty(databaseName: "Test")
        let unlock = UnlockData(masterPassword: "first")

        try VaultWriting.writeAtomically(
            content: content,
            unlockData: unlock,
            to: url,
            backup: false
        )

        let data = try Data(contentsOf: url)
        var reader = KDBXReader(data)
        let reread = try reader.parse(unlockData: unlock)
        #expect(reread.header.encryptionAlgorithm == content.header.encryptionAlgorithm)
    }

    @Test("rekey-style flow: read with old, write with new, re-read with new")
    func rekeyFlow() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("v.kdbx")

        let original = KDBXContent.makeEmpty(databaseName: "Test")
        let oldUnlock = UnlockData(masterPassword: "old")
        let newUnlock = UnlockData(masterPassword: "new")

        try VaultWriting.writeAtomically(content: original, unlockData: oldUnlock, to: url, backup: false)

        // Simulate `db rekey`: parse with old, save with new.
        let firstData = try Data(contentsOf: url)
        var r1 = KDBXReader(firstData)
        let parsed = try r1.parse(unlockData: oldUnlock)

        try VaultWriting.writeAtomically(content: parsed, unlockData: newUnlock, to: url, backup: true)

        // New password works.
        let secondData = try Data(contentsOf: url)
        var r2 = KDBXReader(secondData)
        _ = try r2.parse(unlockData: newUnlock)

        // Old password no longer works.
        var r3 = KDBXReader(secondData)
        #expect(throws: KDBXReader.Error.self) {
            _ = try r3.parse(unlockData: oldUnlock)
        }

        // Backup preserves the original (old password unlocks the .bak).
        let backupURL = url.appendingPathExtension("bak")
        let backupData = try Data(contentsOf: backupURL)
        var r4 = KDBXReader(backupData)
        _ = try r4.parse(unlockData: oldUnlock)
    }

    private func makeTempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("VaultWritingTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
