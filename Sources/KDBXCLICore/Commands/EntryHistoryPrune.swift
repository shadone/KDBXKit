//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry.History {
    struct Prune: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "prune",
            abstract: "Trim an entry's history list. Keep the newest --keep N, or wipe entirely with --all."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(
            name: .customLong("keep"),
            help: ArgumentHelp("Number of newest history items to keep. Older entries are dropped.", valueName: "n")
        )
        var keep: Int?

        @Flag(
            name: .customLong("all"),
            help: "Drop every history entry. Mutually exclusive with --keep."
        )
        var dropAll: Bool = false

        mutating func run() throws {
            if dropAll, keep != nil {
                throw EntryHistoryPruneError.conflictingFlags
            }
            if !dropAll, keep == nil {
                throw EntryHistoryPruneError.missingTarget
            }
            if let keep, keep < 0 {
                throw EntryHistoryPruneError.negativeKeep(keep)
            }

            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let liveEntry = try AddressResolver.findEntry(address, in: content.database)

            var updated = content
            var droppedCount = 0
            let mutated = TreeMutator.mutateEntry(uuid: liveEntry.uuid, in: &updated.database) { entry in
                let before = entry.history.count
                if dropAll {
                    entry.history.removeAll()
                } else if let keep, before > keep {
                    entry.history.removeFirst(before - keep)
                }
                droppedCount = before - entry.history.count
            }
            guard mutated else {
                throw EntryHistoryError.entryVanished(liveEntry.uuid)
            }

            if droppedCount == 0 {
                print("History already within target. No changes.")
                return
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Pruned \(droppedCount) history item(s) from entry \(liveEntry.uuid.uuidString).")
        }
    }
}

enum EntryHistoryPruneError: Error, CustomStringConvertible {
    case conflictingFlags
    case missingTarget
    case negativeKeep(Int)

    var description: String {
        switch self {
        case .conflictingFlags:
            return "--keep and --all are mutually exclusive."
        case .missingTarget:
            return "Pass --keep N to trim or --all to drop every history entry."
        case let .negativeKeep(n):
            return "--keep value must be non-negative (got \(n))."
        }
    }
}
