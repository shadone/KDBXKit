//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXCLICore
@testable import KDBXKit

/// End-to-end coverage for the credential-rotation commands `db rekey` and
/// `db create`. These drive `App` through ArgumentParser on a tmp-file vault,
/// then re-open with the old and new credentials to prove the rotation took
/// effect on disk (old creds fail, new creds succeed). The riskiest branch is
/// `NewCredentialOptions.resolve` deciding between password+keyfile and
/// keyfile-only unlock from an empty stdin — pinned explicitly below.
///
/// Serialized: the stdin-fed tests swap process-global file descriptors.
@Suite("db rekey / db create credential flows", .serialized)
struct RekeyCreateE2ETests {
    private struct Sandbox {
        let dir: URL
        let vault: URL
        let keyFile: URL
        let altKeyFile: URL
        func cleanup() { try? FileManager.default.removeItem(at: dir) }
    }

    /// A vault unlocked by `keyFile` (32 deterministic bytes). `altKeyFile`
    /// holds a *different* 32 bytes for rotation targets; it is written but
    /// not used as the vault's credential.
    private func makeSandbox() throws -> Sandbox {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxcli-rekey-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let vault = dir.appendingPathComponent("v.kdbx")
        let keyFile = dir.appendingPathComponent("key")
        let altKeyFile = dir.appendingPathComponent("key2")
        try Data((0..<32).map { UInt8($0) }).write(to: keyFile)
        try Data((0..<32).map { UInt8(128 + $0) }).write(to: altKeyFile)

        let unlock = try UnlockData(keyFile: Data(contentsOf: keyFile))
        let content = KDBXContent.makeEmpty(databaseName: "test")
        try VaultWriting.writeAtomically(content: content, unlockData: unlock, to: vault, backup: false)
        return Sandbox(dir: dir, vault: vault, keyFile: keyFile, altKeyFile: altKeyFile)
    }

    /// True iff `unlock` opens the vault at `path`.
    private func opens(_ path: String, with unlock: UnlockData) throws -> Bool {
        if case .success = try read(from: path, unlockData: unlock) { return true }
        return false
    }

    /// Run argv with `value` fed on stdin. Delegates to the shared,
    /// process-globally-locked helper so it can't race another suite's
    /// stdin swap (see `CLITestSupport`).
    private func runWithStdin(_ argv: [String], stdin value: String) throws {
        try runAppWithStdin(argv, stdin: value)
    }

    private func run(_ argv: [String]) throws {
        var cmd = try App.parseAsRoot(argv)
        try cmd.run()
    }

    // MARK: - db rekey

    @Test("rekey --new-password-stdin: old key file stops working, new password unlocks")
    func rekeyToPassword() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try runWithStdin(
            ["db", "rekey", sb.vault.path, "--key-file", sb.keyFile.path, "--new-password-stdin"],
            stdin: "new-master-pw"
        )

        let oldUnlock = try UnlockData(keyFile: Data(contentsOf: sb.keyFile))
        #expect(try !opens(sb.vault.path, with: oldUnlock))
        #expect(try opens(sb.vault.path, with: UnlockData(masterPassword: "new-master-pw")))
    }

    @Test("rekey --new-key-file: rotates from one key file to another")
    func rekeyToNewKeyFile() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try run([
            "db", "rekey", sb.vault.path,
            "--key-file", sb.keyFile.path,
            "--new-key-file", sb.altKeyFile.path,
        ])

        let oldUnlock = try UnlockData(keyFile: Data(contentsOf: sb.keyFile))
        let newUnlock = try UnlockData(keyFile: Data(contentsOf: sb.altKeyFile))
        #expect(try !opens(sb.vault.path, with: oldUnlock))
        #expect(try opens(sb.vault.path, with: newUnlock))
    }

    @Test("rekey --new-password-stdin with empty stdin + --new-key-file yields key-file-only unlock")
    func rekeyEmptyStdinWithKeyFileIsKeyFileOnly() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        // Empty stdin is the explicit "I want key-file-only" signal when a
        // --new-key-file is present. The resulting vault must unlock with the
        // new key file ALONE — no password component. This is a deliberate
        // (not warned) behavior; the test documents and pins it.
        try runWithStdin(
            [
                "db", "rekey", sb.vault.path,
                "--key-file", sb.keyFile.path,
                "--new-password-stdin",
                "--new-key-file", sb.altKeyFile.path,
            ],
            stdin: ""
        )

        let newKeyOnly = try UnlockData(keyFile: Data(contentsOf: sb.altKeyFile))
        #expect(try opens(sb.vault.path, with: newKeyOnly))
        // The old key file no longer opens it.
        #expect(try !opens(sb.vault.path, with: UnlockData(keyFile: Data(contentsOf: sb.keyFile))))
    }

    @Test("rekey --new-password-stdin with empty stdin and no key file errors loudly")
    func rekeyEmptyStdinNoKeyFileThrows() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        #expect(throws: NewCredentialError.self) {
            try runWithStdin(
                ["db", "rekey", sb.vault.path, "--key-file", sb.keyFile.path, "--new-password-stdin"],
                stdin: ""
            )
        }
        // The vault is untouched — still opens with the original key file.
        #expect(try opens(sb.vault.path, with: UnlockData(keyFile: Data(contentsOf: sb.keyFile))))
    }

    // MARK: - db create

    @Test("db create --new-key-file produces a vault that the key file opens")
    func createWithKeyFile() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }
        let dest = sb.dir.appendingPathComponent("created.kdbx")

        try run(["db", "create", dest.path, "--new-key-file", sb.keyFile.path, "--name", "Fresh"])

        let unlock = try UnlockData(keyFile: Data(contentsOf: sb.keyFile))
        #expect(try opens(dest.path, with: unlock))
        guard case let .success(content, _) = try read(from: dest.path, unlockData: unlock) else {
            Issue.record("created vault failed to unlock")
            return
        }
        #expect(content.database.meta.databaseName == "Fresh")
    }

    @Test("db create --new-password-stdin produces a vault that the password opens")
    func createWithPassword() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }
        let dest = sb.dir.appendingPathComponent("created-pw.kdbx")

        try runWithStdin(
            ["db", "create", dest.path, "--new-password-stdin"],
            stdin: "create-pw"
        )

        #expect(try opens(dest.path, with: UnlockData(masterPassword: "create-pw")))
        #expect(try !opens(dest.path, with: UnlockData(masterPassword: "wrong-pw")))
    }

    @Test("db create refuses to overwrite an existing file without --force")
    func createRefusesOverwrite() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        // sb.vault already exists. create must refuse rather than clobber it.
        #expect(throws: CreateError.self) {
            try run(["db", "create", sb.vault.path, "--new-key-file", sb.keyFile.path])
        }
        // The original vault still opens with its original key file.
        #expect(try opens(sb.vault.path, with: UnlockData(keyFile: Data(contentsOf: sb.keyFile))))
    }
}
