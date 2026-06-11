//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Off-argv channels for custom protected field values. `--protected-field
/// key=value` puts a secret in `ps` output and shell history; these mirror
/// the stdin/prompt channels the master and entry passwords already use.
struct ProtectedFieldOptions: ParsableArguments {
    @Option(
        name: .customLong("protected-field-stdin"),
        help: ArgumentHelp(
            "Set the protected field <key> to a value read from stdin until EOF (trailing newline trimmed). "
                + "Avoids the argv exposure of --protected-field. Mutually exclusive with the other --*-stdin flags.",
            valueName: "key"
        )
    )
    var protectedFieldStdinKey: String?

    @Option(
        name: .customLong("protected-field-prompt"),
        parsing: .singleValue,
        help: ArgumentHelp(
            "Prompt on the controlling TTY (no echo) for the protected field <key>'s value. Repeatable.",
            valueName: "key"
        )
    )
    var protectedFieldPromptKeys: [String] = []

    /// Resolve the off-argv protected-field assignments. stdin is a single
    /// shared resource, so the stdin channel refuses to coexist with the
    /// master password's or the entry password's stdin flag.
    func resolve(masterUsedStdin: Bool, entryPasswordUsedStdin: Bool) throws -> [EntryFieldAssignment] {
        var assignments: [EntryFieldAssignment] = []
        if let key = protectedFieldStdinKey {
            if masterUsedStdin || entryPasswordUsedStdin {
                throw ProtectedFieldError.stdinBusy
            }
            assignments.append(EntryFieldAssignment(key: key, value: readStdinUntilEOF()))
        }
        for key in protectedFieldPromptKeys {
            guard isatty(STDIN_FILENO) != 0 else {
                throw ProtectedFieldError.notTTY
            }
            assignments.append(EntryFieldAssignment(key: key, value: promptNoEcho("Value for \(key): ")))
        }
        return assignments
    }
}

enum ProtectedFieldError: Error, CustomStringConvertible {
    case stdinBusy
    case notTTY

    var description: String {
        switch self {
        case .stdinBusy:
            return "Cannot read a protected field from stdin while another --*-stdin flag is consuming it. Move one to KDBX_PASSWORD / TTY prompt."
        case .notTTY:
            return "--protected-field-prompt requires a TTY on stdin."
        }
    }
}
