//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Group {
    struct Mv: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "mv",
            abstract: "Reparent a group. Refuses moves that would make a group its own descendant."
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
                "Destination parent group (UUID or path).",
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
            let group = try AddressResolver.findGroup(address, in: content.database)
            if group.uuid == content.database.root.group.uuid {
                throw GroupMvError.cannotMoveRoot
            }

            let destResolved: ResolvedAddress = UUID(uuidString: destination)
                .map(ResolvedAddress.uuid) ?? .path(PathComponents(raw: destination))
            let destGroup = try AddressResolver.findGroup(destResolved, in: content.database)

            // The destructive cycle: moving a group into itself or its
            // descendants would disconnect the subtree from the root.
            if TreeMutator.isDescendant(destGroup.uuid, of: group.uuid, in: content.database) {
                throw GroupMvError.wouldCreateCycle(group.uuid, destGroup.uuid)
            }

            let now = Date()
            var updated = content
            guard let (removed, oldParent) = TreeMutator.removeGroup(uuid: group.uuid, in: &updated.database) else {
                throw GroupMvError.groupVanished(group.uuid)
            }
            if oldParent == destGroup.uuid {
                print("Group \(group.uuid.uuidString) already in destination \(destGroup.uuid.uuidString); no change.")
                return
            }
            var moved = removed
            moved.previousParentGroup = oldParent
            TreeMutator.bumpMoved(&moved.times, now: now)
            guard TreeMutator.insertGroup(moved, intoGroup: destGroup.uuid, in: &updated.database) else {
                throw GroupMvError.destinationVanished(destGroup.uuid)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Moved group \(group.uuid.uuidString) → \(destGroup.uuid.uuidString).")
        }
    }
}

enum GroupMvError: Error, CustomStringConvertible {
    case cannotMoveRoot
    case wouldCreateCycle(UUID, UUID)
    case groupVanished(UUID)
    case destinationVanished(UUID)

    var description: String {
        switch self {
        case .cannotMoveRoot:
            return "Refusing to move the root group."
        case let .wouldCreateCycle(src, dst):
            return "Refusing to move group \(src.uuidString) into its own descendant \(dst.uuidString)."
        case let .groupVanished(uuid):
            return "Group \(uuid.uuidString) disappeared between lookup and move (concurrent edit?)."
        case let .destinationVanished(uuid):
            return "Destination group \(uuid.uuidString) disappeared between lookup and move."
        }
    }
}
