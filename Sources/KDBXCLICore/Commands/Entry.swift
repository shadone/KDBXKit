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
            Show.self,
            Add.self,
            Entry.Set.self,
            Rm.self,
            Mv.self,
            History.self,
        ],
        defaultSubcommand: Ls.self
    )
}
