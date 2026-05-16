//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry.History {
    struct Restore: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "restore",
            abstract: "Restore a prior version of an entry by index. The current state is pushed onto history first, so a restore is itself reversible."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(
            name: .customLong("index"),
            help: ArgumentHelp("History index to restore (0 is oldest).", valueName: "n")
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
            let liveEntry = try AddressResolver.findEntry(address, in: content.database)
            guard liveEntry.history.indices.contains(index) else {
                throw EntryHistoryError.indexOutOfRange(index, count: liveEntry.history.count)
            }

            let now = Date()
            var updated = content
            let meta = updated.database.meta
            let mutated = TreeMutator.mutateEntry(uuid: liveEntry.uuid, in: &updated.database) { entry in
                // Snapshot the *current* (about-to-be-overwritten) state so
                // the restore is reversible. Then copy fields from the chosen
                // history snapshot into the live entry, leaving the history
                // list itself intact (plus the new snapshot we just pushed).
                let preservedHistory = entry.history
                EntryHistory.snapshot(&entry, meta: meta)

                let target = preservedHistory[index]
                entry.iconID = target.iconID
                entry.customIconUUID = target.customIconUUID
                entry.foregroundColor = target.foregroundColor
                entry.backgroundColor = target.backgroundColor
                entry.overrideURL = target.overrideURL
                entry.qualityCheck = target.qualityCheck
                entry.tags = target.tags
                entry.strings = target.strings
                entry.binaries = target.binaries
                entry.autoType = target.autoType
                entry.customData = target.customData

                // previousParentGroup intentionally not restored — the entry
                // hasn't actually moved.

                TreeMutator.bumpModified(&entry.times, now: now)
            }
            guard mutated else {
                throw EntryHistoryError.entryVanished(liveEntry.uuid)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Restored entry \(liveEntry.uuid.uuidString) to history [\(index)]. Previous state pushed to history.")
        }
    }
}
