//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

struct Attach: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "attach",
        abstract: "List, extract, and (in P5) add entry attachments.",
        subcommands: [
            Ls.self,
            Extract.self,
        ],
        defaultSubcommand: Ls.self
    )
}
