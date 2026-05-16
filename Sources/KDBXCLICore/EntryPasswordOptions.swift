//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Source of an entry-level password value. Distinct from `CredentialOptions`
/// (which unlocks the database) so both can coexist on the same command line.
struct EntryPasswordOptions: ParsableArguments {
    @Flag(
        name: .customLong("entry-password-stdin"),
        help: "Read the entry's password from stdin until EOF (trailing newline trimmed). Mutually exclusive with --password-stdin."
    )
    var entryPasswordFromStdin: Bool = false

    @Flag(
        name: .customLong("entry-password-prompt"),
        help: "Prompt for the entry's password on the controlling TTY (no echo). Requires a TTY."
    )
    var entryPasswordPrompt: Bool = false

    /// Resolve the entry password. Returns nil when no source was requested.
    /// `masterUsedStdin` indicates whether the master credential resolution
    /// already consumed stdin — caller passes `credentials.passwordFromStdin`.
    func resolve(masterUsedStdin: Bool) throws -> String? {
        if entryPasswordFromStdin {
            if masterUsedStdin {
                throw EntryPasswordError.bothStdin
            }
            return try readStdinUntilEOF()
        }
        if entryPasswordPrompt {
            guard isatty(fileno(stdin)) != 0 else {
                throw EntryPasswordError.notTTY
            }
            return promptNoEcho("Entry password: ")
        }
        return nil
    }
}

enum EntryPasswordError: Error, CustomStringConvertible {
    case bothStdin
    case notTTY

    var description: String {
        switch self {
        case .bothStdin:
            return "Cannot read both the master and entry passwords from stdin. Move one to KDBX_PASSWORD / TTY prompt."
        case .notTTY:
            return "--entry-password-prompt requires a TTY on stdin."
        }
    }
}

private func readStdinUntilEOF() throws -> String {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard var s = String(data: data, encoding: .utf8) else { return "" }
    if s.hasSuffix("\n") { s.removeLast() }
    if s.hasSuffix("\r") { s.removeLast() }
    return s
}

private func promptNoEcho(_ prompt: String) -> String {
    FileHandle.standardError.write(Data(prompt.utf8))

    var oldTerm = termios()
    let haveTermios = tcgetattr(fileno(stdin), &oldTerm) == 0
    if haveTermios {
        var newTerm = oldTerm
        newTerm.c_lflag &= ~tcflag_t(ECHO)
        _ = tcsetattr(fileno(stdin), TCSAFLUSH, &newTerm)
    }
    defer {
        if haveTermios {
            _ = tcsetattr(fileno(stdin), TCSAFLUSH, &oldTerm)
        }
        FileHandle.standardError.write(Data("\n".utf8))
    }
    return readLine(strippingNewline: true) ?? ""
}
