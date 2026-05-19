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

/// Inputs that produce a *new* `UnlockData` — used by `db rekey` and
/// `db create`. Distinct from `CredentialOptions` (which unlocks the
/// existing file) because both forms can appear on the same command line.
struct NewCredentialOptions: ParsableArguments {
    @Flag(
        name: .customLong("new-password-stdin"),
        help: "Read the new master password from stdin. Mutually exclusive with --password-stdin on the same invocation."
    )
    var newPasswordFromStdin: Bool = false

    @Option(
        name: .customLong("new-key-file"),
        help: ArgumentHelp(
            "Path to a key file used as the new key material. Combine with a new master password or stand alone.",
            valueName: "path"
        )
    )
    var newKeyFilePath: String?

    /// Resolve. `oldUsedStdin` indicates whether the existing credential
    /// resolution already consumed stdin (in which case `--new-password-stdin`
    /// would be ambiguous and we reject it loudly).
    func resolve(oldUsedStdin: Bool) throws -> UnlockData {
        let keyFileData = try loadKeyFile()

        if newPasswordFromStdin {
            if oldUsedStdin {
                throw NewCredentialError.bothStdin
            }
            let password = readStdinUntilEOF()
            if password.isEmpty {
                // Empty stdin means "I want key-file-only unlock". Honor that
                // when a --new-key-file is present; otherwise it's a mistake.
                guard let keyFileData else {
                    throw NewCredentialError.stdinEmpty
                }
                return UnlockData(keyFile: keyFileData)
            }
            return UnlockData(masterPassword: password, keyFile: keyFileData)
        }

        if isatty(STDIN_FILENO) != 0 {
            let password = promptForNewPassword()
            if password.isEmpty, keyFileData == nil {
                throw NewCredentialError.emptyPassword
            }
            if password.isEmpty {
                return UnlockData(keyFile: keyFileData!)
            }
            return UnlockData(masterPassword: password, keyFile: keyFileData)
        }

        // No stdin, no TTY: maybe key-file-only is enough.
        if let keyFileData {
            return UnlockData(keyFile: keyFileData)
        }
        throw NewCredentialError.noSource
    }

    private func loadKeyFile() throws -> Data? {
        guard let path = newKeyFilePath else { return nil }
        do {
            return try Data(contentsOf: URL(filePath: path))
        } catch {
            throw NewCredentialError.keyFileUnreadable(path, underlying: error)
        }
    }
}

enum NewCredentialError: Error, CustomStringConvertible {
    case bothStdin
    case stdinEmpty
    case emptyPassword
    case noSource
    case mismatch
    case keyFileUnreadable(String, underlying: Error)

    var description: String {
        switch self {
        case .bothStdin:
            return "Cannot read both old and new passwords from stdin in the same invocation. Move one of them to KDBX_PASSWORD / --key-file / TTY prompt."
        case .stdinEmpty:
            return "New password expected on stdin but stdin was empty."
        case .emptyPassword:
            return "New password was empty and no --new-key-file was provided."
        case .noSource:
            return "No source for the new credentials. Provide --new-password-stdin, --new-key-file, or run interactively for a TTY prompt."
        case .mismatch:
            return "New password and confirmation did not match."
        case let .keyFileUnreadable(path, error):
            return "Cannot read key file at \(path): \(error.localizedDescription)"
        }
    }
}

private func readStdinUntilEOF() -> String {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard var s = String(data: data, encoding: .utf8) else { return "" }
    if s.hasSuffix("\n") { s.removeLast() }
    if s.hasSuffix("\r") { s.removeLast() }
    return s
}

private func promptForNewPassword() -> String {
    let first = promptNoEcho("New master password: ")
    let confirm = promptNoEcho("Confirm new password: ")
    if first != confirm {
        FileHandle.standardError.write(Data("Error: \(NewCredentialError.mismatch)\n".utf8))
        // Exit non-zero rather than continuing with a half-confirmed credential.
        // `Foundation.exit` is the right choice in a CLI — we have no caller
        // up the stack that can recover meaningfully from this.
        exit(1)
    }
    return first
}

private func promptNoEcho(_ prompt: String) -> String {
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
