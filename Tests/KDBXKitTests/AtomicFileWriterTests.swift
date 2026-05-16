//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("AtomicFileWriter")
struct AtomicFileWriterTests {
    @Test("writes new file when no original exists")
    func newFile() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("vault.kdbx")
        let payload = Data("hello".utf8)

        try AtomicFileWriter.write(payload, to: target)

        #expect(FileManager.default.fileExists(atPath: target.path))
        #expect(try Data(contentsOf: target) == payload)
        let backup = target.appendingPathExtension("bak")
        #expect(!FileManager.default.fileExists(atPath: backup.path))
    }

    @Test("overwrites existing file without backup by default")
    func overwriteNoBackup() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("vault.kdbx")
        try Data("old".utf8).write(to: target)

        try AtomicFileWriter.write(Data("new".utf8), to: target, backup: false)

        #expect(try Data(contentsOf: target) == Data("new".utf8))
        let backup = target.appendingPathExtension("bak")
        #expect(!FileManager.default.fileExists(atPath: backup.path))
    }

    @Test("backup=true preserves prior content as .bak")
    func backupCreated() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("vault.kdbx")
        try Data("old".utf8).write(to: target)

        try AtomicFileWriter.write(Data("new".utf8), to: target, backup: true)

        #expect(try Data(contentsOf: target) == Data("new".utf8))
        let backup = target.appendingPathExtension("bak")
        #expect(try Data(contentsOf: backup) == Data("old".utf8))
    }

    @Test("backup is overwritten on subsequent writes, not accumulated")
    func backupReplaced() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("vault.kdbx")
        try Data("v1".utf8).write(to: target)

        try AtomicFileWriter.write(Data("v2".utf8), to: target, backup: true)
        try AtomicFileWriter.write(Data("v3".utf8), to: target, backup: true)

        #expect(try Data(contentsOf: target) == Data("v3".utf8))
        let backup = target.appendingPathExtension("bak")
        // Backup is the immediately-prior content (v2), not v1.
        #expect(try Data(contentsOf: backup) == Data("v2".utf8))
    }

    @Test("backup=true on a fresh write (no original) skips backup cleanly")
    func backupSkippedWhenNoOriginal() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("vault.kdbx")

        try AtomicFileWriter.write(Data("first".utf8), to: target, backup: true)

        #expect(try Data(contentsOf: target) == Data("first".utf8))
        let backup = target.appendingPathExtension("bak")
        #expect(!FileManager.default.fileExists(atPath: backup.path))
    }

    private func makeTempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("AtomicFileWriterTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
