//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry.History {
    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "show",
            abstract: "Show a single prior version of an entry by index (see `entry history ls`)."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @OptionGroup()
        var secretsOptions: SecretsOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(
            name: .customLong("index"),
            help: ArgumentHelp("Index into the history list (see `entry history ls`). 0 is oldest.", valueName: "n")
        )
        var index: Int

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)
            guard entry.history.indices.contains(index) else {
                throw EntryHistoryError.indexOutOfRange(index, count: entry.history.count)
            }

            // The history snapshot carries the entry's UUID — preserve it so
            // tooling can correlate; the parent path is the live entry's.
            let snap = entry.history[index]
            let parentPath = GroupPath.find(entryUUID: entry.uuid, in: content.database.root.group, prefix: []) ?? []
            let detail = EntryDetailSnapshot(
                entry: snap,
                parentPath: parentPath,
                innerHeader: content.innerHeader,
                showSecrets: secretsOptions.showSecrets
            )
            switch outputOptions.format {
            case .human:
                print("History entry [\(index)] of \(entry.uuid.uuidString):")
                detail.printHuman()
            case .json:
                try printJSON(detail)
            }
        }
    }
}

enum EntryHistoryError: Error, CustomStringConvertible {
    case indexOutOfRange(Int, count: Int)
    case entryVanished(UUID)
    case emptyHistory

    var description: String {
        switch self {
        case let .indexOutOfRange(idx, count):
            if count == 0 {
                return "Entry has no history. Cannot select index \(idx)."
            }
            return "History index \(idx) out of range (0..<\(count))."
        case let .entryVanished(uuid):
            return "Entry \(uuid.uuidString) disappeared between lookup and write (concurrent edit?)."
        case .emptyHistory:
            return "Entry has no history to operate on."
        }
    }
}
