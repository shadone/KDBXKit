//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Create a new entry. Generates a fresh UUID and stamps Times.creationTime/lastModificationTime."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var entryPasswordOptions: EntryPasswordOptions

        @Argument(help: ArgumentHelp("Title of the new entry.", valueName: "title"))
        var title: String

        @Option(
            name: .customLong("in"),
            help: ArgumentHelp(
                "Parent group (UUID or path). Defaults to root.",
                valueName: "uuid-or-path"
            )
        )
        var inGroup: String?

        @Option(name: .customLong("username"), help: "Username field value.")
        var username: String?

        @Option(name: .customLong("url"), help: "URL field value.")
        var url: String?

        @Option(name: .customLong("notes"), help: "Notes field value.")
        var notes: String?

        @Option(
            name: .customLong("tag"),
            parsing: .singleValue,
            help: ArgumentHelp("Add a tag. Repeatable.", valueName: "tag")
        )
        var tags: [String] = []

        @Option(
            name: .customLong("field"),
            parsing: .singleValue,
            help: ArgumentHelp(
                "Add a custom (plaintext-on-disk) field. Repeatable.",
                valueName: "key=value"
            )
        )
        var customFields: [String] = []

        @Option(
            name: .customLong("protected-field"),
            parsing: .singleValue,
            help: ArgumentHelp(
                "Add a custom field stored inner-cipher-encrypted on save. Repeatable. "
                    + "NOTE: the value is visible in `ps` and shell history; prefer "
                    + "--protected-field-stdin / --protected-field-prompt for real secrets.",
                valueName: "key=value"
            )
        )
        var protectedFields: [String] = []

        @OptionGroup
        var protectedFieldOptions: ProtectedFieldOptions

        @Option(
            name: .customLong("icon"),
            help: ArgumentHelp("KeePass icon ID (UInt32). Defaults to 0.", valueName: "id")
        )
        var iconID: UInt32 = 0

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            // Resolve parent group (default: root).
            let parentGroupUUID = try resolveParentUUID(in: content.database)

            // Parse field assignments. Reject standard-field names so users
            // don't end up with a duplicate Title that round-trips weirdly.
            let regularCustom = try customFields.map(EntryFieldAssignment.parse)
            var protectedCustom = try protectedFields.map(EntryFieldAssignment.parse)
            protectedCustom += try protectedFieldOptions.resolve(
                masterUsedStdin: commonOptions.credentials.passwordFromStdin,
                entryPasswordUsedStdin: entryPasswordOptions.entryPasswordFromStdin
            )
            for f in regularCustom + protectedCustom where EntryField.standardKeys.contains(f.key) {
                throw EntryFieldAssignmentError.standardFieldNotAllowed(f.key)
            }

            // Resolve the entry password (optional). When neither stdin nor
            // prompt was requested, the Password field is left as "" — the
            // standard KeePass behavior for "no password yet".
            let entryPassword = try entryPasswordOptions.resolve(
                masterUsedStdin: commonOptions.credentials.passwordFromStdin
            )

            let now = Date()
            var entry = KDBX.Entry(
                uuid: UUID(),
                iconID: iconID,
                tags: tags,
                times: KDBX.Times(
                    creationTime: now,
                    lastModificationTime: now,
                    lastAccessTime: now,
                    expires: false,
                    usageCount: 0,
                    locationChanged: now
                ),
                strings: []
            )

            // Standard fields. Title is always present even if empty.
            EntryField.setRegular(EntryField.title, title, on: &entry)
            EntryField.setRegular(EntryField.userName, username ?? "", on: &entry)
            EntryField.setRegular(EntryField.url, url ?? "", on: &entry)
            EntryField.setRegular(EntryField.notes, notes ?? "", on: &entry)
            EntryField.setProtected(EntryField.password, entryPassword ?? "", on: &entry)

            for f in regularCustom {
                EntryField.setRegular(f.key, f.value, on: &entry)
            }
            for f in protectedCustom {
                EntryField.setProtected(f.key, f.value, on: &entry)
            }

            var updated = content
            guard TreeMutator.insertEntry(entry, intoGroup: parentGroupUUID, in: &updated.database) else {
                throw EntryAddError.parentVanished(parentGroupUUID)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Added entry \(entry.uuid.uuidString) (\(title)) under group \(parentGroupUUID.uuidString).")
        }

        private func resolveParentUUID(in db: KDBX) throws -> UUID {
            guard let raw = inGroup else { return db.root.group.uuid }
            let resolved: ResolvedAddress = UUID(uuidString: raw)
                .map(ResolvedAddress.uuid) ?? .path(PathComponents(raw: raw))
            return try AddressResolver.findGroup(resolved, in: db).uuid
        }
    }
}

enum EntryAddError: Error, CustomStringConvertible {
    case parentVanished(UUID)

    var description: String {
        switch self {
        case let .parentVanished(uuid):
            return "Parent group \(uuid.uuidString) disappeared between lookup and insert (concurrent edit?)."
        }
    }
}
