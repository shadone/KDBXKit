//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "show",
            abstract: "Show a single entry's fields, binaries, and metadata."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @OptionGroup()
        var secretsOptions: SecretsOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)
            let parentPath = GroupPath.find(entryUUID: entry.uuid, in: content.database.root.group, prefix: []) ?? []

            let snapshot = EntryDetailSnapshot(
                entry: entry,
                parentPath: parentPath,
                innerHeader: content.innerHeader,
                showSecrets: secretsOptions.showSecrets
            )

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }
    }
}
