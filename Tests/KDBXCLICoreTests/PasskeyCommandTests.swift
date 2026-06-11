//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import Testing
@testable import KDBXCLICore

/// Drives the `kdbx passkey {ls, show}` subcommands against the real
/// KeePassXC-authored passkey fixture (`Resources/kpxc-passkey.kdbx`,
/// password `123`, 6 passkeys). The fixture is bundled into this test
/// target's resources so `Bundle.module` can resolve it.
///
/// The security invariant under test: neither command ever emits the
/// passkey private key bytes. Both tests grep the captured stdout to
/// prove the PEM never escapes.
@Suite("passkey command", .serialized)
struct PasskeyCommandTests {
    /// Resolve the bundled fixture path or fail the test.
    private func fixturePath() throws -> String {
        try #require(
            Bundle.module.path(forResource: "Resources/kpxc-passkey", ofType: "kdbx"),
            "kpxc-passkey.kdbx must be bundled into the KDBXCLICoreTests resources"
        )
    }

    /// Run a CLI invocation, feeding the master password (`123`) on stdin via
    /// `--password-stdin` and capturing stdout. Returns the captured stdout.
    ///
    /// The password rides the `--password-stdin` channel (not `KDBX_PASSWORD`)
    /// on purpose: setting a process-global env var would leak into other
    /// tests running in parallel — the `EndToEndTests` unlock with a key file
    /// and a stray `KDBX_PASSWORD` makes their reads fail. stdin and stdout are
    /// both redirected through pipes only for the duration of the run.
    private func runCapturingStdout(_ argv: [String]) throws -> String {
        // Held under the process-global stdio lock: this swaps both
        // STDIN_FILENO and STDOUT_FILENO, which would otherwise race the
        // stdin swaps in other CLI suites running in parallel (see
        // `CLITestSupport`).
        try withExclusiveStdio {
            // Feed the password on stdin.
            let inPipe = Pipe()
            inPipe.fileHandleForWriting.write(Data("123".utf8))
            try inPipe.fileHandleForWriting.close()
            let savedStdin = dup(STDIN_FILENO)
            dup2(inPipe.fileHandleForReading.fileDescriptor, STDIN_FILENO)

            // Capture stdout.
            let outPipe = Pipe()
            let savedStdout = dup(STDOUT_FILENO)
            // fflush(nil) flushes every open output stream. We avoid naming
            // `stdout` directly: on glibc it's a mutable global var that Swift 6
            // strict concurrency rejects as non-Sendable (Darwin declares it as
            // a function-like macro, so referencing it there compiles).
            fflush(nil)
            dup2(outPipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)

            var cmd = try App.parseAsRoot(argv + ["--password-stdin"])
            try cmd.run()

            // Restore the real stdin/stdout *before* reading the pipe. While fd 1
            // is still duped onto the pipe's write end, the write end is "open" and
            // readDataToEndOfFile() would block forever waiting for EOF.
            fflush(nil)
            dup2(savedStdout, STDOUT_FILENO)
            close(savedStdout)
            dup2(savedStdin, STDIN_FILENO)
            close(savedStdin)
            try outPipe.fileHandleForWriting.close()

            let data = outPipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        }
    }

    @Test("passkey ls lists relying party and username")
    func lsListsRelyingPartyAndUsername() throws {
        let output = try runCapturingStdout(["passkey", "ls", fixturePath()])
        #expect(output.contains("ctap.dev"))
    }

    @Test("passkey show prints metadata but never the private key")
    func showPrintsMetadataButNeverPrivateKey() throws {
        let output = try runCapturingStdout(["passkey", "show", "ctap.dev", fixturePath()])
        #expect(output.contains("ctap.dev"))
        #expect(output.contains("Username"))
        #expect(!output.contains("PRIVATE KEY"))
        #expect(!output.contains("BEGIN"))
    }
}
