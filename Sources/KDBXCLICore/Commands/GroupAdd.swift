//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Group {
    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Create a new group as a child of another group (default: root)."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @Argument(help: ArgumentHelp("Name of the new group.", valueName: "name"))
        var name: String

        @Option(
            name: .customLong("in"),
            help: ArgumentHelp(
                "Parent group (UUID or path). Defaults to root.",
                valueName: "uuid-or-path"
            )
        )
        var inGroup: String?

        @Option(name: .customLong("notes"), help: "Free-form notes for the group.")
        var notes: String?

        @Option(
            name: .customLong("icon"),
            help: ArgumentHelp("KeePass icon ID (UInt32). Defaults to 48 (folder).", valueName: "id")
        )
        var iconID: UInt32 = 48

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let parentUUID: UUID
            if let raw = inGroup {
                let resolved: ResolvedAddress = UUID(uuidString: raw)
                    .map(ResolvedAddress.uuid) ?? .path(PathComponents(raw: raw))
                parentUUID = try AddressResolver.findGroup(resolved, in: content.database).uuid
            } else {
                parentUUID = content.database.root.group.uuid
            }

            let now = Date()
            let newGroup = KDBX.Group(
                uuid: UUID(),
                name: name,
                notes: notes,
                iconID: iconID,
                times: KDBX.Times(
                    creationTime: now,
                    lastModificationTime: now,
                    lastAccessTime: now,
                    expires: false,
                    usageCount: 0,
                    locationChanged: now
                ),
                isExpanded: true
            )

            var updated = content
            guard TreeMutator.insertGroup(newGroup, intoGroup: parentUUID, in: &updated.database) else {
                throw GroupAddError.parentVanished(parentUUID)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Added group \(newGroup.uuid.uuidString) (\(name)) under \(parentUUID.uuidString).")
        }
    }
}

enum GroupAddError: Error, CustomStringConvertible {
    case parentVanished(UUID)

    var description: String {
        switch self {
        case let .parentVanished(uuid):
            return "Parent group \(uuid.uuidString) disappeared between lookup and insert (concurrent edit?)."
        }
    }
}
