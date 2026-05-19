//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct EmptyRecycleBin: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "empty-recycle-bin",
            abstract: "Hard-delete every entry and subgroup under the vault's Recycle Bin group, recording DeletedObject sync records."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            // The recycle bin is identified by Meta.recycleBinUUID. A zero UUID
            // (or no UUID at all) means "no recycle bin in this vault".
            let bin = recycleBinGroup(in: content.database)
            guard let bin else {
                let snapshot = EmptyRecycleBinResult(found: false, removedEntries: 0, removedGroups: 0)
                try emit(snapshot)
                return
            }

            // Walk the bin subtree first to collect UUIDs that need DeletedObject
            // sync records, then clear the bin's contents in-place.
            let now = Date()
            var deletedUUIDs: [UUID] = []
            collectAllUUIDs(in: bin, into: &deletedUUIDs)

            var updated = content
            updated.database = clearingRecycleBin(in: content.database, binUUID: bin.uuid)
            updated.database.root.deletedObjects.append(contentsOf: deletedUUIDs.map {
                KDBX.DeletedObject(uuid: $0, deletionTime: now)
            })

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            let removedEntries = countEntries(in: bin)
            let removedGroups = countGroups(in: bin)
            let result = EmptyRecycleBinResult(found: true, removedEntries: removedEntries, removedGroups: removedGroups)
            try emit(result)
        }

        private func emit(_ result: EmptyRecycleBinResult) throws {
            switch outputOptions.format {
            case .human:
                result.printHuman()
            case .json:
                try printJSON(result)
            }
        }

        private func recycleBinGroup(in db: KDBX) -> KDBX.Group? {
            RecycleBin.find(in: db)
        }

        private func collectAllUUIDs(in group: KDBX.Group, into ids: inout [UUID]) {
            RecycleBin.collectUUIDs(in: group, into: &ids)
        }

        private func countEntries(in group: KDBX.Group) -> Int {
            RecycleBin.countEntries(in: group)
        }

        private func countGroups(in group: KDBX.Group) -> Int {
            RecycleBin.countGroups(in: group)
        }

        private func clearingRecycleBin(in db: KDBX, binUUID: UUID) -> KDBX {
            RecycleBin.cleared(in: db, binUUID: binUUID)
        }
    }
}

/// Pure helpers for recycle-bin manipulation. Free of CLI plumbing so they're
/// directly unit-testable.
enum RecycleBin {
    static func find(in db: KDBX) -> KDBX.Group? {
        guard let id = db.meta.recycleBinUUID, !id.isZeroUUID else { return nil }
        return findGroup(uuid: id, in: db.root.group)
    }

    static func findGroup(uuid: UUID, in group: KDBX.Group) -> KDBX.Group? {
        if group.uuid == uuid { return group }
        for child in group.groups {
            if let found = findGroup(uuid: uuid, in: child) { return found }
        }
        return nil
    }

    static func collectUUIDs(in group: KDBX.Group, into ids: inout [UUID]) {
        for entry in group.entries {
            ids.append(entry.uuid)
        }
        for child in group.groups {
            ids.append(child.uuid)
            collectUUIDs(in: child, into: &ids)
        }
    }

    static func countEntries(in group: KDBX.Group) -> Int {
        var n = group.entries.count
        for child in group.groups {
            n += countEntries(in: child)
        }
        return n
    }

    static func countGroups(in group: KDBX.Group) -> Int {
        var n = 0
        for child in group.groups {
            n += 1
            n += countGroups(in: child)
        }
        return n
    }

    /// Returns a copy of `db` with the recycle bin group's children cleared.
    /// The bin itself is kept (matching KeePass behavior — emptying ≠ removing
    /// the bin).
    static func cleared(in db: KDBX, binUUID: UUID) -> KDBX {
        var newDB = db
        newDB.root.group = clearing(in: db.root.group, binUUID: binUUID)
        return newDB
    }

    private static func clearing(in group: KDBX.Group, binUUID: UUID) -> KDBX.Group {
        var rewritten = group
        if group.uuid == binUUID {
            rewritten.entries = []
            rewritten.groups = []
            return rewritten
        }
        rewritten.groups = group.groups.map { clearing(in: $0, binUUID: binUUID) }
        return rewritten
    }
}

struct EmptyRecycleBinResult: Encodable {
    let found: Bool
    let removedEntries: Int
    let removedGroups: Int

    func printHuman() {
        if !found {
            print("No recycle bin configured (or its UUID is zero). Nothing to do.")
            return
        }
        if removedEntries == 0, removedGroups == 0 {
            print("Recycle bin already empty.")
            return
        }
        print("Emptied recycle bin: removed \(removedEntries) entry(ies) and \(removedGroups) group(s).")
    }
}
