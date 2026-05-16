//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Mv: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "mv",
            abstract: "Move an entry to a different group. Stamps previousParentGroup and Times.locationChanged."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(
            name: .customLong("to"),
            help: ArgumentHelp(
                "Destination group (UUID or path).",
                valueName: "uuid-or-path"
            )
        )
        var destination: String

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)
            let destResolved: ResolvedAddress = UUID(uuidString: destination)
                .map(ResolvedAddress.uuid) ?? .path(PathComponents(raw: destination))
            let destGroup = try AddressResolver.findGroup(destResolved, in: content.database)

            let now = Date()
            var updated = content

            guard let (removed, oldParent) = TreeMutator.removeEntry(uuid: entry.uuid, in: &updated.database) else {
                throw EntryMvError.entryVanished(entry.uuid)
            }
            if oldParent == destGroup.uuid {
                // Same parent — nothing to do, don't bump locationChanged.
                print("Entry \(entry.uuid.uuidString) already in group \(destGroup.uuid.uuidString); no change.")
                return
            }
            var moved = removed
            moved.previousParentGroup = oldParent
            TreeMutator.bumpMoved(&moved.times, now: now)
            guard TreeMutator.insertEntry(moved, intoGroup: destGroup.uuid, in: &updated.database) else {
                throw EntryMvError.destinationVanished(destGroup.uuid)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Moved entry \(entry.uuid.uuidString) → \(destGroup.uuid.uuidString).")
        }
    }
}

enum EntryMvError: Error, CustomStringConvertible {
    case entryVanished(UUID)
    case destinationVanished(UUID)

    var description: String {
        switch self {
        case let .entryVanished(uuid):
            return "Entry \(uuid.uuidString) disappeared between lookup and move (concurrent edit?)."
        case let .destinationVanished(uuid):
            return "Destination group \(uuid.uuidString) disappeared between lookup and move."
        }
    }
}
