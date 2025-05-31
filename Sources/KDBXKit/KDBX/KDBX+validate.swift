//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        var allCustomIcons: Set<UUID> = []
        for customIcon in meta.customIcons {
            if allCustomIcons.contains(customIcon.uuid) {
                results.append(.warning("Several CustomIcons reuse the same UUID: \(customIcon.uuid.uuidString)"))
            }
            allCustomIcons.insert(customIcon.uuid)
        }

        var allGroups: Set<UUID> = []
        visitGroups(in: root.group) { group in
            if allGroups.contains(group.uuid) {
                results.append(.warning("Several Groups reuses the same UUID: \(group.uuid.uuidString)"))
            }
            if let previousParentGroup = group.previousParentGroup {
                if !allGroups.contains(previousParentGroup) {
                    results.append(.warning("PreviousParentGroup points to non-existent group: \(previousParentGroup.uuidString)"))
                }
            }
            allGroups.insert(group.uuid)
        }

        func validateGroupExists(_ uuid: UUID?, nodePath: String) {
            if let uuid, !uuid.isZero, !allGroups.contains(uuid) {
                results.append(.warning("\(nodePath) points to a Group that does not exist: \(uuid.uuidString)"))
            }
        }

        var allEntries: Set<UUID> = []
        visitEntries(in: root.group) { entry in
            if allEntries.contains(entry.uuid) {
                results.append(.warning("Several Entries reuses the same UUID: \(entry.uuid.uuidString)"))
            }
            allEntries.insert(entry.uuid)
        }

        func validateEntryExists(_ uuid: UUID?, nodePath: String) {
            if let uuid, !allEntries.contains(uuid) {
                results.append(.warning("\(nodePath) points to an Entry that does not exist: \(uuid.uuidString)"))
            }
        }

        let duplicateUUIDs = allGroups.intersection(allEntries)
        if !duplicateUUIDs.isEmpty {
            results.append(.warning("Several Entries/Groups use the same UUID: \(duplicateUUIDs.map(\.uuidString).joined(separator: ", "))"))
        }

        // MARK: Check that RecycleBinUUID,etc exists

        validateGroupExists(meta.recycleBinUUID, nodePath: "Meta.RecycleBinUUID")
        validateGroupExists(meta.entryTemplatesGroup, nodePath: "Meta.EntryTemplatesGroup")
        validateGroupExists(meta.lastSelectedGroup, nodePath: "Meta.LastSelectedGroup")
        validateGroupExists(meta.lastTopVisibleGroup, nodePath: "Meta.LastTopVisibleGroup")

        visitGroups(in: root.group) { group in
            results += group.validate()

            // MARK: Check that all Groups that valid Custom Icon

            if let customIconUUID = group.customIconUUID {
                if !allCustomIcons.contains(customIconUUID) {
                    results.append(.warning("Group[\(group.uuid.uuidString)].CustomIconUUID references a non existing Custom Icon: \(customIconUUID.uuidString)"))
                }
            }

            // MARK: Check that all Groups have valid LastTopVisibleEntry

            if let lastTopVisibleEntry = group.lastTopVisibleEntry {
                if !allEntries.contains(lastTopVisibleEntry) {
                    results.append(.warning("Group[\(group.uuid.uuidString)].LastTopVisibleEntry references a non existing entry: \(lastTopVisibleEntry.uuidString)"))
                }
            }

            // MARK: Check that all Groups have valid PreviousParentGroup

            if let previousParentGroup = group.previousParentGroup {
                if !allGroups.contains(previousParentGroup) {
                    results.append(.warning("Group[\(group.uuid.uuidString)].PreviousParentGroup references a non existing group: \(previousParentGroup.uuidString)"))
                }
            }
        }

        visitEntries(in: root.group) { entry in
            results += entry.validate()

            // MARK: Check that all Entries that valid Custom Icon

            if let customIconUUID = entry.customIconUUID {
                if !allCustomIcons.contains(customIconUUID) {
                    results.append(.warning("Entry[\(entry.uuid)].CustomIconUUID references a non existing Custom Icon: \(customIconUUID.uuidString)"))
                }
            }

            // MARK: Check that all Entries have valid PreviousParentGroup

            if let previousParentGroup = entry.previousParentGroup {
                if !allGroups.contains(previousParentGroup) {
                    results.append(.warning("Entry[\(entry.uuid.uuidString)].PreviousParentGroup references a non existing group: \(previousParentGroup.uuidString)"))
                }
            }
        }

        return results
    }
}
