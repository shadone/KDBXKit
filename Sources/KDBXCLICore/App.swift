//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation

/// Root `kdbx` command. Public so the thin executable wrapper (and tests)
/// can dispatch into it. The `@main` annotation lives on the executable
/// target's `main.swift`, not on this type.
public struct App: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "kdbx",
        abstract: "A command-line tool to work with KeePass databases.",
        version: "1.3.0",
        subcommands: [
            DB.self,
            Entry.self,
            Group.self,
            Attach.self,
            Passkey.self,
        ]
    )

    public init() { }
}
