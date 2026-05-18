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
        ],
        defaultSubcommand: Info.self
    )
}
