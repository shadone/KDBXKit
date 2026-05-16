//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

struct Group: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "group",
        abstract: "Inspect and manipulate group hierarchy.",
        subcommands: [
            Ls.self,
            Tree.self,
            Add.self,
            Rm.self,
            Mv.self,
            Group.Set.self,
        ],
        defaultSubcommand: Ls.self
    )
}
