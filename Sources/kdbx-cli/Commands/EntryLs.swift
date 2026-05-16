//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List entries in the vault."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let snapshot = EntryListSnapshot(content: content)

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }
    }
}
