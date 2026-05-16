//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Group {
    struct Set: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "set",
            abstract: "Rename or edit an existing group. Stamps Times.lastModificationTime."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(name: .customLong("name"), help: "Replace the group's name.")
        var name: String?

        @Option(name: .customLong("notes"), help: "Replace the group's notes (free-form text).")
        var notes: String?

        @Option(
            name: .customLong("icon"),
            help: ArgumentHelp("Replace the KeePass icon ID.", valueName: "id")
        )
        var iconID: UInt32?

        mutating func run() throws {
            // No-op fast path: zero mutation flags → no rewrite, no time bump.
            // Matches `entry set`'s behavior so noisy invocations don't churn
            // the file's modification timestamp.
            let hasMutation = name != nil || notes != nil || iconID != nil
            if !hasMutation {
                print("No mutation flags supplied; nothing to do.")
                return
            }

            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let target = try AddressResolver.findGroup(address, in: content.database)

            let now = Date()
            var updated = content
            let found = TreeMutator.mutateGroup(uuid: target.uuid, in: &updated.database) { group in
                if let name { group.name = name }
                if let notes { group.notes = notes }
                if let iconID { group.iconID = iconID }
                TreeMutator.bumpModified(&group.times, now: now)
            }
            guard found else {
                throw GroupSetError.groupVanished(target.uuid)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Updated group \(target.uuid.uuidString).")
        }
    }
}

enum GroupSetError: Error, CustomStringConvertible {
    case groupVanished(UUID)

    var description: String {
        switch self {
        case let .groupVanished(uuid):
            return "Group \(uuid.uuidString) disappeared between lookup and write (concurrent edit?)."
        }
    }
}
