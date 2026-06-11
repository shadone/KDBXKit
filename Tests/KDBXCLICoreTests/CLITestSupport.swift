//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
@testable import KDBXCLICore

/// Shared plumbing for CLI tests that feed a command via `stdin`.
///
/// `STDIN_FILENO` is a process-global resource. `.serialized` only orders
/// tests *within* one suite — Swift Testing still runs different suites in
/// parallel, so two suites that each `dup2` a pipe onto `STDIN_FILENO`
/// clobber each other (one command reads the other's bytes). This lock
/// serializes the swap-run-restore critical section across *every* suite, so
/// only one stdin-swapping command runs at a time process-wide.
private let stdioSwapLock = NSLock()

/// Run `body` while holding the process-global stdio lock. Any test that
/// `dup2`s a pipe onto `STDIN_FILENO`/`STDOUT_FILENO` must wrap its
/// swap-run-restore section in this so it can't race a swap from another
/// suite running in parallel.
func withExclusiveStdio<R>(_ body: () throws -> R) rethrows -> R {
    stdioSwapLock.lock()
    defer { stdioSwapLock.unlock() }
    return try body()
}

/// Run `argv` through `App` with `value` presented on `stdin`. The fd swap is
/// restored before returning and the whole critical section is held under the
/// process-global stdio lock.
func runAppWithStdin(_ argv: [String], stdin value: String) throws {
    try withExclusiveStdio {
        let inPipe = Pipe()
        inPipe.fileHandleForWriting.write(Data(value.utf8))
        try inPipe.fileHandleForWriting.close()
        let savedStdin = dup(STDIN_FILENO)
        dup2(inPipe.fileHandleForReading.fileDescriptor, STDIN_FILENO)
        defer {
            dup2(savedStdin, STDIN_FILENO)
            close(savedStdin)
        }
        var cmd = try App.parseAsRoot(argv)
        try cmd.run()
    }
}
