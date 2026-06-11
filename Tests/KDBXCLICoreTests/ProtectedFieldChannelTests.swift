//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXCLICore
@testable import KDBXKit

/// `--protected-field key=value` puts a secret on argv (visible in `ps`
/// and shell history). Master and entry passwords were carefully routed
/// off argv; custom protected fields need the same stdin/prompt channels.
/// Serialized: the stdin test swaps process-global file descriptors.
@Suite("protected-field stdin/prompt channels", .serialized)
struct ProtectedFieldChannelTests {
    private struct Sandbox {
        let dir: URL
        let vault: URL
        let keyFile: URL
        func cleanup() { try? FileManager.default.removeItem(at: dir) }
    }

    private func makeSandbox() throws -> Sandbox {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxcli-pf-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let vault = dir.appendingPathComponent("v.kdbx")
        let keyFile = dir.appendingPathComponent("key")
        let keyBytes = Data((0..<32).map { UInt8($0) })
        try keyBytes.write(to: keyFile)
        let unlock = try UnlockData(keyFile: keyBytes)
        let content = KDBXContent.makeEmpty(databaseName: "test")
        try VaultWriting.writeAtomically(content: content, unlockData: unlock, to: vault, backup: false)
        return Sandbox(dir: dir, vault: vault, keyFile: keyFile)
    }

    private func reopen(_ sandbox: Sandbox) throws -> KDBXContent {
        let keyBytes = try Data(contentsOf: sandbox.keyFile)
        let unlock = try UnlockData(keyFile: keyBytes)
        guard case let .success(content, _) = try read(from: sandbox.vault.path, unlockData: unlock) else {
            throw AppError.wrongCredentials
        }
        return content
    }

    /// Run argv with `value` fed on stdin. Delegates to the shared,
    /// process-globally-locked helper so it can't race another suite's
    /// stdin swap (see `CLITestSupport`).
    private func runWithStdin(_ argv: [String], stdin value: String) throws {
        try runAppWithStdin(argv, stdin: value)
    }

    @Test("entry add --protected-field-stdin reads the secret from stdin, not argv")
    func protectedFieldViaStdin() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        try runWithStdin(
            [
                "entry",
                "add",
                sb.vault.path,
                "API",
                "--key-file",
                sb.keyFile.path,
                "--protected-field-stdin",
                "ApiKey",
            ],
            stdin: "s3cret-via-stdin"
        )

        let content = try reopen(sb)
        let entry = try #require(content.database.root.group.entries.first(where: {
            $0.strings.first(where: { $0.key == "Title" })?.value.revealedString == "API"
        }))
        let field = try #require(entry.strings.first(where: { $0.key == "ApiKey" }))
        #expect(field.value.revealedString == "s3cret-via-stdin")
        // Protected on disk: a reopened encrypted field is never .regular.
        if case .regular = field.value {
            Issue.record("ApiKey was written plaintext-on-disk")
        }
    }

    @Test("entry set --protected-field-stdin updates an existing entry")
    func protectedFieldViaStdinOnSet() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }

        var cmd = try App.parseAsRoot(
            ["entry", "add", sb.vault.path, "API", "--key-file", sb.keyFile.path]
        )
        try cmd.run()
        try runWithStdin(
            [
                "entry",
                "set",
                sb.vault.path,
                "/API",
                "--key-file",
                sb.keyFile.path,
                "--protected-field-stdin",
                "ApiKey",
            ],
            stdin: "rotated-secret"
        )

        let content = try reopen(sb)
        let entry = try #require(content.database.root.group.entries.first)
        #expect(entry.strings.first(where: { $0.key == "ApiKey" })?.value.revealedString == "rotated-secret")
    }

    @Test("stdin channel refuses to share stdin with the master password")
    func stdinConflictRejected() throws {
        var options = ProtectedFieldOptions()
        options.protectedFieldStdinKey = "ApiKey"
        #expect(throws: ProtectedFieldError.self) {
            _ = try options.resolve(masterUsedStdin: true, entryPasswordUsedStdin: false)
        }
        #expect(throws: ProtectedFieldError.self) {
            _ = try options.resolve(masterUsedStdin: false, entryPasswordUsedStdin: true)
        }
    }

    @Test("standard field names are rejected on the stdin channel too")
    func standardKeyRejected() throws {
        let sb = try makeSandbox()
        defer { sb.cleanup() }
        #expect(throws: EntryFieldAssignmentError.self) {
            try runWithStdin(
                [
                    "entry",
                    "add",
                    sb.vault.path,
                    "API",
                    "--key-file",
                    sb.keyFile.path,
                    "--protected-field-stdin",
                    "Password",
                ],
                stdin: "nope"
            )
        }
    }
}
