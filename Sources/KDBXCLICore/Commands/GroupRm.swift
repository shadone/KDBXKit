//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Group {
    struct Rm: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rm",
            abstract: "Move a group (and its subtree) to the Recycle Bin, or hard-delete with --permanent."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Flag(
            name: .customLong("permanent"),
            help: "Hard-delete instead of moving to the Recycle Bin. Records DeletedObject sync entries for every UUID in the subtree."
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
            let group = try AddressResolver.findGroup(address, in: content.database)

            if group.uuid == content.database.root.group.uuid {
                throw GroupRmError.cannotRemoveRoot
            }
            if let binID = content.database.meta.recycleBinUUID,
               !binID.isZeroUUID, binID == group.uuid
            {
                throw GroupRmError.cannotRemoveRecycleBinGroup
            }

            let now = Date()
            var updated = content

            let binUUID: UUID?
            if permanent {
                binUUID = nil
            } else {
                // Refuse to "move into the bin" if the group is already
                // inside the bin subtree.
                if let existingBinID = content.database.meta.recycleBinUUID,
                   !existingBinID.isZeroUUID,
                   TreeMutator.isDescendant(group.uuid, of: existingBinID, in: content.database)
                {
                    throw GroupRmError.alreadyInBin(group.uuid)
                }
                binUUID = RecycleBinManager.ensureBin(in: &updated, now: now)
                // Refuse the impossible case where the freshly-ensured bin
                // happens to be the very group we'd be removing.
                if let binUUID, binUUID == group.uuid {
                    throw GroupRmError.cannotRemoveRecycleBinGroup
                }
            }

            guard let (removed, oldParent) = TreeMutator.removeGroup(uuid: group.uuid, in: &updated.database) else {
                throw GroupRmError.groupVanished(group.uuid)
            }

            if let binUUID {
                var moved = removed
                moved.previousParentGroup = oldParent
                TreeMutator.bumpMoved(&moved.times, now: now)
                guard TreeMutator.insertGroup(moved, intoGroup: binUUID, in: &updated.database) else {
                    throw GroupRmError.binVanished(binUUID)
                }

                try VaultWriting.writeAtomically(
                    content: updated,
                    unlockData: unlock,
                    to: URL(filePath: commonOptions.filepath),
                    backup: backupOptions.backup
                )
                print("Moved group \(group.uuid.uuidString) to Recycle Bin (\(binUUID.uuidString)).")
            } else {
                var deleted: [UUID] = [removed.uuid]
                collectSubtreeUUIDs(in: removed, into: &deleted)
                updated.database.root.deletedObjects.append(contentsOf: deleted.map {
                    KDBX.DeletedObject(uuid: $0, deletionTime: now)
                })

                try VaultWriting.writeAtomically(
                    content: updated,
                    unlockData: unlock,
                    to: URL(filePath: commonOptions.filepath),
                    backup: backupOptions.backup
                )
                print("Permanently deleted group \(group.uuid.uuidString) and \(deleted.count - 1) descendant(s).")
            }
        }

        private func collectSubtreeUUIDs(in group: KDBX.Group, into ids: inout [UUID]) {
            for entry in group.entries {
                ids.append(entry.uuid)
            }
            for child in group.groups {
                ids.append(child.uuid)
                collectSubtreeUUIDs(in: child, into: &ids)
            }
        }
    }
}

enum GroupRmError: Error, CustomStringConvertible {
    case cannotRemoveRoot
    case cannotRemoveRecycleBinGroup
    case alreadyInBin(UUID)
    case groupVanished(UUID)
    case binVanished(UUID)

    var description: String {
        switch self {
        case .cannotRemoveRoot:
            return "Refusing to remove the root group."
        case .cannotRemoveRecycleBinGroup:
            return "Refusing to remove the Recycle Bin group itself. Use `db empty-recycle-bin` to clear its contents."
        case let .alreadyInBin(uuid):
            return "Group \(uuid.uuidString) is already in the Recycle Bin. Pass --permanent to hard-delete."
        case let .groupVanished(uuid):
            return "Group \(uuid.uuidString) disappeared between lookup and remove (concurrent edit?)."
        case let .binVanished(uuid):
            return "Recycle Bin group \(uuid.uuidString) disappeared while moving the group into it."
        }
    }
}
