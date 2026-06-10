//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

/// Integration tests that drive `App` end-to-end on a tmp-file vault: parse
/// argv via ArgumentParser, run the command, re-open the vault, and assert
/// the on-disk state. Covers the run() ordering — snapshot before mutation,
/// recycle-bin auto-create, GC ref renumbering — that the focused unit tests
/// can't see.
///
/// Master credentials use `--key-file` so tests never touch stdin, KDBX_PASSWORD,
/// or a TTY. Entry passwords are skipped (the `Password` field defaults to "").
@Suite("App end-to-end")
struct EndToEndTests {
    // MARK: - Fixture plumbing

    /// Per-test sandbox: vault path + key-file path inside a fresh tmp dir.
    private struct Sandbox {
        let dir: URL
        let vault: URL
        let keyFile: URL

        func cleanup() {
            try? FileManager.default.removeItem(at: dir)
        }
    }

    private func makeSandbox() throws -> Sandbox {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxcli-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let vault = dir.appendingPathComponent("v.kdbx")
        let keyFile = dir.appendingPathComponent("key")

        // 32 bytes of fixed key material — deterministic so test failures are
        // reproducible. The bytes are not secret-shaped; tests don't care.
        let keyBytes = Data((0..<32).map { UInt8($0) })
        try keyBytes.write(to: keyFile)

        let unlock = try UnlockData(keyFile: keyBytes)
        let content = KDBXContent.makeEmpty(databaseName: "test")
        try VaultWriting.writeAtomically(content: content, unlockData: unlock, to: vault, backup: false)

        return Sandbox(dir: dir, vault: vault, keyFile: keyFile)
    }

    /// Re-read the vault from disk with the sandbox's key file. Each test
    /// re-opens between commands so the assertions reflect serialized state,
    /// not in-memory mutations.
    private func reopen(_ sandbox: Sandbox) throws -> KDBXContent {
        let keyBytes = try Data(contentsOf: sandbox.keyFile)
        let unlock = try UnlockData(keyFile: keyBytes)
        guard case let .success(content, _) = try read(from: sandbox.vault.path, unlockData: unlock) else {
            Issue.record("vault failed to unlock with the sandbox key file")
            throw EndToEndError.unlockFailed
        }
        return content
    }

    /// Run a single CLI invocation. Each call goes through ArgumentParser so
    /// we exercise the same argv parsing that real users hit.
    private func run(_ argv: [String]) throws {
        var cmd = try App.parseAsRoot(argv)
        try cmd.run()
    }

    private enum EndToEndError: Error { case unlockFailed }

    // MARK: - Entry add / set / mv / rm

    @Test("db migrate on a 4.x vault is a clean no-op")
    func dbMigrate_onModernVaultIsNoOp() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        // makeSandbox() produces a fresh 4.1 vault via
        // KDBXContent.makeEmpty. `db migrate` must recognize the
        // already-modern format and exit without touching the file —
        // safe to run over a directory of mixed-vintage vaults.
        let before = try Data(contentsOf: sb.vault)

        try run(["db", "migrate", sb.vault.path, "--key-file", sb.keyFile.path])

        let after = try Data(contentsOf: sb.vault)
        // Exact-byte equality: the no-op path takes the don't-rewrite
        // branch, so we don't even pay the salt-regeneration cost.
        #expect(before == after)

        // Vault is still openable and reports 4.1 — pins that
        // `migrate` doesn't somehow corrupt non-target files.
        let content = try reopen(sb)
        #expect(content.header.formatVersion == .v4_1)
    }

    @Test("entry add inserts under the named group with a fresh UUID and stamped Times")
    func entryAddInsertsUnderGroup() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "add", sb.vault.path, "Banking", "--in", "/", "--key-file", sb.keyFile.path])
        try run([
            "entry",
            "add",
            sb.vault.path,
            "Chase",
            "--in",
            "/Banking",
            "--username",
            "alice",
            "--url",
            "https://chase.com",
            "--tag",
            "finance",
            "--key-file",
            sb.keyFile.path,
        ])

        let content = try reopen(sb)
        let banking = content.database.root.group.groups.first(where: { $0.name == "Banking" })
        let chase = try #require(banking?.entries.first(where: { e in
            e.strings.first(where: { $0.key == "Title" })?.value.revealedString == "Chase"
        }))
        #expect(chase.tags == ["finance"])
        #expect(chase.times?.creationTime != nil)
        #expect(chase.times?.lastModificationTime != nil)
    }

    @Test("entry set snapshots the prior state into history before mutating")
    func entrySetSnapshotsHistory() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "Mail", "--username", "v1", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v2", "--key-file", sb.keyFile.path])

        let content = try reopen(sb)
        let mail = try #require(content.database.root.group.entries.first(where: {
            $0.strings.first(where: { $0.key == "Title" })?.value.revealedString == "Mail"
        }))
        // Live entry should carry v2; history[0] should carry v1.
        #expect(mail.strings.first(where: { $0.key == "UserName" })?.value.revealedString == "v2")
        #expect(mail.history.count == 1)
        #expect(mail.history[0].strings.first(where: { $0.key == "UserName" })?.value.revealedString == "v1")
        // The history snapshot itself must not carry nested history.
        #expect(mail.history[0].history.isEmpty)
    }

    @Test("entry set --no-history skips the snapshot")
    func entrySetSkipsHistoryWhenAsked() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "Mail", "--username", "v1", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v2", "--no-history", "--key-file", sb.keyFile.path])

        let content = try reopen(sb)
        let mail = try #require(content.database.root.group.entries.first)
        #expect(mail.history.isEmpty)
    }

    @Test("entry set with no mutation flags is a true no-op (no rewrite, no time bump)")
    func entrySetNoOpFastPath() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "Mail", "--username", "alice", "--key-file", sb.keyFile.path])
        let before = try reopen(sb)
        let entryBefore = try #require(before.database.root.group.entries.first)
        let timesBefore = entryBefore.times

        // No mutation flags — should print "nothing to do" and not rewrite.
        try run(["entry", "set", sb.vault.path, "/Mail", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let entryAfter = try #require(after.database.root.group.entries.first)
        #expect(entryAfter.times == timesBefore)
        #expect(entryAfter.history.isEmpty)
    }

    @Test("entry mv stamps previousParentGroup and Times.locationChanged")
    func entryMvStampsTimes() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "add", sb.vault.path, "A", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["group", "add", sb.vault.path, "B", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["entry", "add", sb.vault.path, "X", "--in", "/A", "--key-file", sb.keyFile.path])

        let beforeContent = try reopen(sb)
        let groupA = try #require(beforeContent.database.root.group.groups.first(where: { $0.name == "A" }))

        try run(["entry", "mv", sb.vault.path, "/A/X", "--to", "/B", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let groupAAfter = try #require(after.database.root.group.groups.first(where: { $0.name == "A" }))
        let groupB = try #require(after.database.root.group.groups.first(where: { $0.name == "B" }))
        #expect(groupAAfter.entries.isEmpty)
        let moved = try #require(groupB.entries.first)
        #expect(moved.previousParentGroup == groupA.uuid)
        #expect(moved.times?.locationChanged != nil)
    }

    @Test("entry rm moves to a freshly-created Recycle Bin")
    func entryRmCreatesBinAndMoves() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "X", "--in", "/", "--key-file", sb.keyFile.path])
        let beforeContent = try reopen(sb)
        #expect(beforeContent.database.meta.recycleBinUUID == nil
            || beforeContent.database.meta.recycleBinUUID?.isZeroUUID == true)

        try run(["entry", "rm", sb.vault.path, "/X", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let binID = try #require(after.database.meta.recycleBinUUID)
        #expect(!binID.isZeroUUID)
        let bin = try #require(TreeMutator.findGroup(uuid: binID, in: after.database.root.group))
        let trashed = try #require(bin.entries.first)
        #expect(trashed.previousParentGroup == after.database.root.group.uuid)
    }

    @Test("entry rm --permanent records a DeletedObject and skips the bin")
    func entryRmPermanent() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "X", "--in", "/", "--key-file", sb.keyFile.path])
        let beforeContent = try reopen(sb)
        let entryID = try #require(beforeContent.database.root.group.entries.first?.uuid)

        try run(["entry", "rm", sb.vault.path, "/X", "--permanent", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        // No Recycle Bin was created (we asked for permanent).
        #expect(after.database.meta.recycleBinUUID == nil
            || after.database.meta.recycleBinUUID?.isZeroUUID == true)
        #expect(after.database.root.group.entries.isEmpty)
        #expect(after.database.root.deletedObjects.contains(where: { $0.uuid == entryID }))
    }

    // MARK: - Group set / rm / mv

    @Test("group set --name renames the group and bumps Times.lastModificationTime")
    func groupSetRenames() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "add", sb.vault.path, "Old", "--in", "/", "--key-file", sb.keyFile.path])
        let before = try reopen(sb)
        let oldGroup = try #require(before.database.root.group.groups.first(where: { $0.name == "Old" }))
        let modBefore = oldGroup.times?.lastModificationTime

        try run(["group", "set", sb.vault.path, "/Old", "--name", "New", "--notes", "renamed", "--icon", "49", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let renamed = try #require(after.database.root.group.groups.first(where: { $0.uuid == oldGroup.uuid }))
        #expect(renamed.name == "New")
        #expect(renamed.notes == "renamed")
        #expect(renamed.iconID == 49)
        // Mod time advanced. If the test runs in the same wall-clock second
        // the comparison still holds because makeEmpty stamped now and our
        // set call stamped a later now; both come from Date().
        if let modBefore, let modAfter = renamed.times?.lastModificationTime {
            #expect(modAfter >= modBefore)
        }
    }

    @Test("group set with no flags is a true no-op (no rewrite)")
    func groupSetNoOpFastPath() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "add", sb.vault.path, "X", "--in", "/", "--key-file", sb.keyFile.path])
        let before = try reopen(sb)
        let groupBefore = try #require(before.database.root.group.groups.first(where: { $0.name == "X" }))
        let timesBefore = groupBefore.times

        try run(["group", "set", sb.vault.path, "/X", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let groupAfter = try #require(after.database.root.group.groups.first(where: { $0.uuid == groupBefore.uuid }))
        #expect(groupAfter.times == timesBefore)
        #expect(groupAfter.name == "X")
    }

    @Test("group set works on the root group itself")
    func groupSetWorksOnRoot() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "set", sb.vault.path, "/", "--name", "Renamed Root", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        #expect(after.database.root.group.name == "Renamed Root")
    }

    // MARK: - Group rm / mv

    @Test("group mv refuses to move a group into its own descendant")
    func groupMvRefusesCycle() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "add", sb.vault.path, "Outer", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["group", "add", sb.vault.path, "Inner", "--in", "/Outer", "--key-file", sb.keyFile.path])

        #expect(throws: Error.self) {
            try run(["group", "mv", sb.vault.path, "/Outer", "--to", "/Outer/Inner", "--key-file", sb.keyFile.path])
        }

        // The tree shape is unchanged after the failed move.
        let after = try reopen(sb)
        #expect(after.database.root.group.groups.contains(where: { $0.name == "Outer" }))
    }

    @Test("group rm --permanent records DeletedObject for every UUID in the subtree")
    func groupRmPermanentRecordsAllUUIDs() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["group", "add", sb.vault.path, "Top", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["group", "add", sb.vault.path, "Sub", "--in", "/Top", "--key-file", sb.keyFile.path])
        try run(["entry", "add", sb.vault.path, "E1", "--in", "/Top", "--key-file", sb.keyFile.path])
        try run(["entry", "add", sb.vault.path, "E2", "--in", "/Top/Sub", "--key-file", sb.keyFile.path])

        let before = try reopen(sb)
        let top = try #require(before.database.root.group.groups.first(where: { $0.name == "Top" }))
        let sub = try #require(top.groups.first(where: { $0.name == "Sub" }))
        let e1 = try #require(top.entries.first(where: { e in
            e.strings.first(where: { $0.key == "Title" })?.value.revealedString == "E1"
        }))
        let e2 = try #require(sub.entries.first)
        let expected = Set([top.uuid, sub.uuid, e1.uuid, e2.uuid])

        try run(["group", "rm", sb.vault.path, "/Top", "--permanent", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        #expect(!after.database.root.group.groups.contains(where: { $0.name == "Top" }))
        let recorded = Set(after.database.root.deletedObjects.map(\.uuid))
        #expect(expected.isSubset(of: recorded))
    }

    // MARK: - Attachments

    @Test("attach add stores bytes in the inner header and references them by index")
    func attachAddCreatesRef() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "E", "--in", "/", "--key-file", sb.keyFile.path])
        let payload = sb.dir.appendingPathComponent("p.txt")
        try Data("hello".utf8).write(to: payload)

        try run(["attach", "add", sb.vault.path, "/E", "--file", payload.path, "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        #expect(after.innerHeader.binaryContent.count == 1)
        let entry = try #require(after.database.root.group.entries.first)
        let binary = try #require(entry.binaries.first)
        #expect(binary.key == "p.txt")
        if case let .ref(idx) = binary.value {
            #expect(idx == 0)
            #expect(after.innerHeader.binaryContent[Int(idx)].data == Data("hello".utf8))
        } else {
            Issue.record("expected ref attachment, got inline")
        }
    }

    @Test("attach add dedups byte-identical blobs across entries")
    func attachAddDedups() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        let payload = sb.dir.appendingPathComponent("p.txt")
        try Data("hello".utf8).write(to: payload)

        try run(["entry", "add", sb.vault.path, "E1", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["entry", "add", sb.vault.path, "E2", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["attach", "add", sb.vault.path, "/E1", "--file", payload.path, "--key-file", sb.keyFile.path])
        try run(["attach", "add", sb.vault.path, "/E2", "--file", payload.path, "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        // Identical bytes → one inner-header slot, two ref'ing entries.
        #expect(after.innerHeader.binaryContent.count == 1)
        let refs: [UInt32] = after.database.root.group.entries.compactMap { entry in
            if case let .ref(idx) = entry.binaries.first?.value { return idx } else { return nil }
        }
        #expect(refs == [0, 0])
    }

    @Test("attach rm --gc drops the orphan binary and renumbers surviving refs")
    func attachRmGCRenumbersRefs() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        let a = sb.dir.appendingPathComponent("a.bin")
        let b = sb.dir.appendingPathComponent("b.bin")
        try Data("aaa".utf8).write(to: a)
        try Data("bbb".utf8).write(to: b)

        try run(["entry", "add", sb.vault.path, "E", "--in", "/", "--key-file", sb.keyFile.path])
        try run(["attach", "add", sb.vault.path, "/E", "--file", a.path, "--key-file", sb.keyFile.path])
        try run(["attach", "add", sb.vault.path, "/E", "--file", b.path, "--key-file", sb.keyFile.path])

        // Sanity: two binaries, refs 0 and 1.
        let mid = try reopen(sb)
        #expect(mid.innerHeader.binaryContent.count == 2)

        // Remove a.bin with --gc. b.bin was at ref=1; after GC it must point to 0.
        try run(["attach", "rm", sb.vault.path, "/E", "a.bin", "--gc", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        #expect(after.innerHeader.binaryContent.count == 1)
        #expect(after.innerHeader.binaryContent[0].data == Data("bbb".utf8))

        let entry = try #require(after.database.root.group.entries.first)
        #expect(entry.binaries.count == 1)
        if case let .ref(idx) = entry.binaries[0].value {
            #expect(idx == 0)
        } else {
            Issue.record("expected ref attachment")
        }
    }

    // MARK: - Entry history navigation

    @Test("entry history restore brings back a prior version and pushes current to history")
    func historyRestoreIsReversible() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "Mail", "--username", "v1", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v2", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v3", "--key-file", sb.keyFile.path])

        // Before restore: live=v3, history=[v1, v2].
        let beforeRestore = try reopen(sb)
        let mail = try #require(beforeRestore.database.root.group.entries.first)
        #expect(mail.history.count == 2)

        // Restore index 0 (v1). The current state (v3) gets snapshotted first,
        // so after restore: live=v1, history=[v1, v2, v3].
        try run(["entry", "history", "restore", sb.vault.path, "/Mail", "--index", "0", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let restored = try #require(after.database.root.group.entries.first)
        #expect(restored.strings.first(where: { $0.key == "UserName" })?.value.revealedString == "v1")
        #expect(restored.history.count == 3)
        // The newly-captured snapshot (formerly live) should be the newest entry.
        #expect(restored.history.last?.strings.first(where: { $0.key == "UserName" })?.value.revealedString == "v3")
    }

    @Test("entry history prune --keep N drops the oldest beyond the cap")
    func historyPruneKeep() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "Mail", "--username", "v1", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v2", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v3", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v4", "--key-file", sb.keyFile.path])

        try run(["entry", "history", "prune", sb.vault.path, "/Mail", "--keep", "1", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let mail = try #require(after.database.root.group.entries.first)
        // Only the newest history entry (v3, the one captured by the final set) survives.
        #expect(mail.history.count == 1)
        #expect(mail.history[0].strings.first(where: { $0.key == "UserName" })?.value.revealedString == "v3")
    }

    @Test("entry history prune --all wipes history")
    func historyPruneAll() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run(["entry", "add", sb.vault.path, "Mail", "--username", "v1", "--key-file", sb.keyFile.path])
        try run(["entry", "set", sb.vault.path, "/Mail", "--username", "v2", "--key-file", sb.keyFile.path])
        try run(["entry", "history", "prune", sb.vault.path, "/Mail", "--all", "--key-file", sb.keyFile.path])

        let after = try reopen(sb)
        let mail = try #require(after.database.root.group.entries.first)
        #expect(mail.history.isEmpty)
    }
}
