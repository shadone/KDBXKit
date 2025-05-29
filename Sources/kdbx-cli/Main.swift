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
      abstract: "A command-line tool to work with KeePass databases.",
      version: "0.0.1",
      subcommands: [
        Info.self,
        XML.self,
        Get.self,
      ],
      // A default subcommand, when provided, is automatically selected if a
      // subcommand is not given on the command line.
      defaultSubcommand: Info.self
    )
}
