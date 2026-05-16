//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

struct Entry: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "entry",
        abstract: "Read and manipulate individual entries.",
        subcommands: [
            Ls.self,
        ],
        defaultSubcommand: Ls.self
    )
}
