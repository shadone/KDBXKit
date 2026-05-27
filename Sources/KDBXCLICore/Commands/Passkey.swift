//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

struct Passkey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "passkey",
        abstract: "Inspect passkeys stored in the database (KPEX_PASSKEY_* fields).",
        subcommands: [Ls.self, Show.self],
        defaultSubcommand: Ls.self
    )
}
