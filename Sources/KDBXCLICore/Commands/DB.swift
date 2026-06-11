//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

struct DB: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "db",
        abstract: "Database-level operations (header, XML dump, validation, conversion).",
        subcommands: [
            Info.self,
            XML.self,
            Validate.self,
            Rekey.self,
            SetKDF.self,
            SetCipher.self,
            SetCompression.self,
            Create.self,
            EmptyRecycleBin.self,
            Migrate.self,
            OpenBench.self,
        ]
        // No defaultSubcommand: with one set, ArgumentParser routes
        // `kdbx db --help` to the default's help and hides the
        // subcommand list. Discoverability of `xml`, `validate`, etc.
        // matters more than the `kdbx db <file>` shortcut for `info`.
    )
}
