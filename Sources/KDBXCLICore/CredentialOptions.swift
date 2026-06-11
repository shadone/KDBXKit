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

enum CredentialError: Error, CustomStringConvertible {
    case noCredentialsAndNotTTY
    case keyFileUnreadable(String, underlying: Error)
    case stdinEmpty

    var description: String {
        switch self {
        case .noCredentialsAndNotTTY:
            return "No credentials provided and stdin is not a TTY (use --password-stdin, KDBX_PASSWORD, or --key-file)."
        case let .keyFileUnreadable(path, underlying):
            return "Cannot read key file at \(path): \(underlying.localizedDescription)"
        case .stdinEmpty:
            return "Password expected on stdin but stdin was empty."
        }
    }
}

/// Resolves vault credentials from flags, env, stdin, and the TTY.
///
/// Precedence (highest to lowest):
///   1. `--password-stdin`
///   2. `KDBX_PASSWORD` env var (unless `--no-env`)
///   3. TTY no-echo prompt when stdin is a TTY (only if `requireUnlock` is true)
///
/// `--key-file <path>` combines with any of the above, or stands alone for
/// keyfile-only unlock.
struct CredentialOptions: ParsableArguments {
    @Flag(
        name: .customLong("password-stdin"),
        help: "Read the master password from stdin until EOF (trailing newline trimmed)."
    )
    var passwordFromStdin: Bool = false

    @Flag(
        name: .customLong("no-env"),
        help: ArgumentHelp(
            "Ignore the KDBX_PASSWORD environment variable.",
            discussion: "Environment variables are visible to same-user processes "
                + "(ps -E, /proc/<pid>/environ) and often end up in CI logs — prefer "
                + "--password-stdin or --key-file where that matters."
        )
    )
    var noEnv: Bool = false

    @Option(
        name: .customLong("key-file"),
        help: ArgumentHelp("Path to a key file used as additional unlock material.", valueName: "path")
    )
    var keyFilePath: String?

    /// Resolve credentials, requiring a non-nil result. Use for commands that
    /// can't operate header-only. Throws when nothing is supplied and stdin
    /// isn't a TTY.
    func resolveRequired() throws -> UnlockData {
        // resolve(requireUnlock: true) never returns nil — every path either
        // returns a value or throws. Force-unwrap is safe.
        try resolve(requireUnlock: true)!
    }

    /// Resolve credentials. Returns nil when no source was supplied AND
    /// `requireUnlock` is false (e.g. header-only inspection).
    func resolve(requireUnlock: Bool) throws -> UnlockData? {
        let keyFileData = try loadKeyFile()

        if passwordFromStdin {
            let password = readPasswordFromStdin()
            if password.isEmpty {
                throw CredentialError.stdinEmpty
            }
            return try UnlockData(masterPassword: password, keyFile: keyFileData)
        }

        if !noEnv,
           let password = ProcessInfo.processInfo.environment["KDBX_PASSWORD"],
           !password.isEmpty
        {
            return try UnlockData(masterPassword: password, keyFile: keyFileData)
        }

        if let keyFileData {
            // Key file alone is a valid unlock.
            return try UnlockData(keyFile: keyFileData)
        }

        guard requireUnlock else {
            return nil
        }

        if isatty(STDIN_FILENO) != 0 {
            let password = promptForPassword()
            return UnlockData(masterPassword: password)
        }

        throw CredentialError.noCredentialsAndNotTTY
    }

    private func loadKeyFile() throws -> Data? {
        guard let path = keyFilePath else { return nil }
        do {
            return try Data(contentsOf: URL(filePath: path))
        } catch {
            throw CredentialError.keyFileUnreadable(path, underlying: error)
        }
    }
}

private func readPasswordFromStdin() -> String {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard var s = String(data: data, encoding: .utf8) else { return "" }
    // Strip a single trailing newline so `echo "pw" | kdbx ...` works as expected.
    if s.hasSuffix("\n") { s.removeLast() }
    if s.hasSuffix("\r") { s.removeLast() }
    return s
}

private func promptForPassword(prompt: String = "Master password: ") -> String {
    // Write the prompt to stderr so it doesn't contaminate piped stdout.
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
