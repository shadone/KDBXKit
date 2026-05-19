//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Rm: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rm",
            abstract: "Move an entry to the Recycle Bin (or hard-delete with --permanent)."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Flag(
            name: .customLong("permanent"),
            help: "Hard-delete instead of moving to the Recycle Bin. Records a DeletedObject sync entry."
        )
        var permanent: Bool = false

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)

            let now = Date()
            var updated = content

            // Honor the vault's Recycle Bin policy: explicit-disabled bin or
            // --permanent both go through the hard-delete path. Otherwise we
            // ensure the bin exists and move the entry there.
            let binUUID: UUID?
            if permanent {
                binUUID = nil
            } else {
                // Refuse to "move into the bin" if the entry is already in
                // the bin subtree. Check before ensureBin so we don't create
                // a bin only to bail out.
                if let existingBinID = content.database.meta.recycleBinUUID,
                   !existingBinID.isZeroUUID,
                   isInRecycleBin(entry: entry.uuid, binUUID: existingBinID, in: content.database)
                {
                    throw EntryRmError.alreadyInBin(entry.uuid)
                }
                binUUID = RecycleBinManager.ensureBin(in: &updated, now: now)
            }

            guard let (removed, oldParent) = TreeMutator.removeEntry(uuid: entry.uuid, in: &updated.database) else {
                throw EntryRmError.entryVanished(entry.uuid)
            }

            if let binUUID {
                var moved = removed
                moved.previousParentGroup = oldParent
                TreeMutator.bumpMoved(&moved.times, now: now)
                guard TreeMutator.insertEntry(moved, intoGroup: binUUID, in: &updated.database) else {
                    throw EntryRmError.binVanished(binUUID)
                }
                try VaultWriting.writeAtomically(
                    content: updated,
                    unlockData: unlock,
                    to: URL(filePath: commonOptions.filepath),
                    backup: backupOptions.backup
                )
                print("Moved entry \(entry.uuid.uuidString) to Recycle Bin (\(binUUID.uuidString)).")
            } else {
                updated.database.root.deletedObjects.append(
                    KDBX.DeletedObject(uuid: removed.uuid, deletionTime: now)
                )
                try VaultWriting.writeAtomically(
                    content: updated,
                    unlockData: unlock,
                    to: URL(filePath: commonOptions.filepath),
                    backup: backupOptions.backup
                )
                print("Permanently deleted entry \(entry.uuid.uuidString).")
            }
        }

        /// True if `entry` is anywhere inside the subtree rooted at the bin.
        private func isInRecycleBin(entry: UUID, binUUID: UUID, in db: KDBX) -> Bool {
            guard let bin = TreeMutator.findGroup(uuid: binUUID, in: db.root.group) else { return false }
            return containsEntry(uuid: entry, in: bin)
        }

        private func containsEntry(uuid: UUID, in group: KDBX.Group) -> Bool {
            if group.entries.contains(where: { $0.uuid == uuid }) { return true }
            for child in group.groups where containsEntry(uuid: uuid, in: child) {
                return true
            }
            return false
        }
    }
}

enum EntryRmError: Error, CustomStringConvertible {
    case entryVanished(UUID)
    case binVanished(UUID)
    case alreadyInBin(UUID)

    var description: String {
        switch self {
        case let .entryVanished(uuid):
            return "Entry \(uuid.uuidString) disappeared between lookup and remove (concurrent edit?)."
        case let .binVanished(uuid):
            return "Recycle Bin group \(uuid.uuidString) disappeared while moving the entry into it."
        case let .alreadyInBin(uuid):
            return "Entry \(uuid.uuidString) is already in the Recycle Bin. Pass --permanent to hard-delete."
        }
    }
}
