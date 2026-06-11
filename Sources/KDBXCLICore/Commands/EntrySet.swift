//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Set: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "set",
            abstract: "Modify fields, tags, and metadata on an existing entry. Stamps Times.lastModificationTime."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var entryPasswordOptions: EntryPasswordOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(name: .customLong("title"), help: "Replace the entry's Title field.")
        var title: String?

        @Option(name: .customLong("username"), help: "Replace the entry's UserName field.")
        var username: String?

        @Option(name: .customLong("url"), help: "Replace the entry's URL field.")
        var url: String?

        @Option(name: .customLong("notes"), help: "Replace the entry's Notes field.")
        var notes: String?

        @Option(
            name: .customLong("field"),
            parsing: .singleValue,
            help: ArgumentHelp(
                "Set or replace a custom (plaintext-on-disk) field. Repeatable.",
                valueName: "key=value"
            )
        )
        var customFields: [String] = []

        @Option(
            name: .customLong("protected-field"),
            parsing: .singleValue,
            help: ArgumentHelp(
                "Set or replace a custom field stored inner-cipher-encrypted on save. Repeatable. "
                    + "NOTE: the value is visible in `ps` and shell history; prefer "
                    + "--protected-field-stdin / --protected-field-prompt for real secrets.",
                valueName: "key=value"
            )
        )
        var protectedFields: [String] = []

        @OptionGroup
        var protectedFieldOptions: ProtectedFieldOptions

        @Option(
            name: .customLong("remove-field"),
            parsing: .singleValue,
            help: ArgumentHelp("Remove a custom field by key. Repeatable. Refuses standard KDBX keys.", valueName: "key")
        )
        var removeFields: [String] = []

        @Option(
            name: .customLong("add-tag"),
            parsing: .singleValue,
            help: ArgumentHelp("Add a tag (idempotent). Repeatable.", valueName: "tag")
        )
        var addTags: [String] = []

        @Option(
            name: .customLong("remove-tag"),
            parsing: .singleValue,
            help: ArgumentHelp("Remove a tag if present. Repeatable.", valueName: "tag")
        )
        var removeTags: [String] = []

        @Option(
            name: .customLong("set-tags"),
            parsing: .singleValue,
            help: ArgumentHelp(
                "Replace the entire tag list. Repeatable; multiple --set-tags args concatenate. Mutually exclusive with --add-tag / --remove-tag.",
                valueName: "tag"
            )
        )
        var setTags: [String] = []

        @Option(
            name: .customLong("icon"),
            help: ArgumentHelp("Replace the KeePass icon ID.", valueName: "id")
        )
        var iconID: UInt32?

        @Flag(
            name: .customLong("no-history"),
            help: "Skip the usual history snapshot. The mutation overwrites the live entry without leaving a prior version."
        )
        var skipHistory: Bool = false

        mutating func run() throws {
            if !setTags.isEmpty, !(addTags.isEmpty && removeTags.isEmpty) {
                throw EntrySetError.tagsConflict
            }

            let regularCustom = try customFields.map(EntryFieldAssignment.parse)
            var protectedCustom = try protectedFields.map(EntryFieldAssignment.parse)
            protectedCustom += try protectedFieldOptions.resolve(
                masterUsedStdin: commonOptions.credentials.passwordFromStdin,
                entryPasswordUsedStdin: entryPasswordOptions.entryPasswordFromStdin
            )
            for f in regularCustom + protectedCustom where EntryField.standardKeys.contains(f.key) {
                throw EntryFieldAssignmentError.standardFieldNotAllowed(f.key)
            }
            for k in removeFields where EntryField.standardKeys.contains(k) {
                throw EntrySetError.cannotRemoveStandardField(k)
            }

            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let target = try AddressResolver.findEntry(address, in: content.database)

            let newPassword = try entryPasswordOptions.resolve(
                masterUsedStdin: commonOptions.credentials.passwordFromStdin
            )

            // No-op fast path: if the user supplied no mutation flags, do
            // not snapshot, do not bump times, do not rewrite the file.
            // Distinguishes "I changed nothing" from "I changed nothing but
            // bumped modification time", which would silently churn vaults.
            let hasMutation = title != nil || username != nil || url != nil || notes != nil
                || newPassword != nil || iconID != nil
                || !regularCustom.isEmpty || !protectedCustom.isEmpty
                || !removeFields.isEmpty
                || !addTags.isEmpty || !removeTags.isEmpty || !setTags.isEmpty
            if !hasMutation {
                print("No mutation flags supplied; nothing to do.")
                return
            }

            let now = Date()
            var updated = content
            let snapshotHistory = !skipHistory
            let meta = updated.database.meta
            let found = TreeMutator.mutateEntry(uuid: target.uuid, in: &updated.database) { entry in
                if snapshotHistory {
                    EntryHistory.snapshot(&entry, meta: meta)
                }

                if let title { EntryField.setRegular(EntryField.title, title, on: &entry) }
                if let username { EntryField.setRegular(EntryField.userName, username, on: &entry) }
                if let url { EntryField.setRegular(EntryField.url, url, on: &entry) }
                if let notes { EntryField.setRegular(EntryField.notes, notes, on: &entry) }
                if let newPassword {
                    EntryField.setProtected(EntryField.password, newPassword, on: &entry)
                }
                for f in regularCustom {
                    EntryField.setRegular(f.key, f.value, on: &entry)
                }
                for f in protectedCustom {
                    EntryField.setProtected(f.key, f.value, on: &entry)
                }
                for k in removeFields {
                    EntryField.remove(k, from: &entry)
                }

                if !setTags.isEmpty {
                    entry.tags = setTags
                } else {
                    for t in addTags where !entry.tags.contains(t) {
                        entry.tags.append(t)
                    }
                    for t in removeTags {
                        entry.tags.removeAll { $0 == t }
                    }
                }

                if let iconID { entry.iconID = iconID }
                TreeMutator.bumpModified(&entry.times, now: now)
            }
            guard found else {
                // The address resolved a moment ago; if this fails the tree
                // was mutated concurrently between resolve and write.
                throw EntrySetError.entryVanished(target.uuid)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Updated entry \(target.uuid.uuidString).")
        }
    }
}

enum EntrySetError: Error, CustomStringConvertible {
    case tagsConflict
    case cannotRemoveStandardField(String)
    case entryVanished(UUID)

    var description: String {
        switch self {
        case .tagsConflict:
            return "--set-tags is mutually exclusive with --add-tag / --remove-tag."
        case let .cannotRemoveStandardField(key):
            return "Refusing to remove standard KDBX field `\(key)`. Set it to an empty value instead."
        case let .entryVanished(uuid):
            return "Entry \(uuid.uuidString) disappeared between lookup and write (concurrent edit?)."
        }
    }
}
