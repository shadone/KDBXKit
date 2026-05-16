//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

@main
struct App: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kdbx",
        abstract: "A command-line tool to work with KeePass databases.",
        version: "0.1.0",
        subcommands: [
            DB.self,
            Entry.self,
            Group.self,
            Attach.self,
        ]
    )
}
