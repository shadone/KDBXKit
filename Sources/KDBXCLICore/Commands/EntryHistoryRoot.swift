//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

extension Entry {
    struct History: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "history",
            abstract: "List, inspect, restore, and prune prior versions of an entry.",
            subcommands: [
                Ls.self,
                Show.self,
                Restore.self,
                Prune.self,
            ],
            defaultSubcommand: Ls.self
        )
    }
}
