//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Shared secret-input plumbing for CredentialOptions, NewCredentialOptions,
// EntryPasswordOptions, and ProtectedFieldOptions — one copy so a fix (e.g.
// the termios restore) can't drift between channels.

func readStdinUntilEOF() -> String {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard var s = String(data: data, encoding: .utf8) else { return "" }
    if s.hasSuffix("\n") { s.removeLast() }
    if s.hasSuffix("\r") { s.removeLast() }
    return s
}

/// No-echo TTY prompt. The prompt is written to stderr (stdout may be a
/// pipe carrying command output) and the terminal's echo flag is restored
/// in a defer.
func promptNoEcho(_ prompt: String) -> String {
    FileHandle.standardError.write(Data(prompt.utf8))

    var oldTerm = termios()
    let haveTermios = tcgetattr(STDIN_FILENO, &oldTerm) == 0
    if haveTermios {
        var newTerm = oldTerm
        newTerm.c_lflag &= ~tcflag_t(ECHO)
        _ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &newTerm)
    }
    defer {
        if haveTermios {
            _ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTerm)
        }
        FileHandle.standardError.write(Data("\n".utf8))
    }

    return readLine(strippingNewline: true) ?? ""
}
