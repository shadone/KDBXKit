//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

struct Attach: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "attach",
        abstract: "List, extract, add, and remove entry attachments.",
        subcommands: [
            Ls.self,
            Extract.self,
            Add.self,
            Rm.self,
        ],
        defaultSubcommand: Ls.self
    )
}
