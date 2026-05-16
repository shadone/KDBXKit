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
            allGroups.insert(group.uuid)
        }

        // All existence helpers treat the zero UUID as "no reference" per
        // the official KDBX semantics — most reference fields use the zero
        // UUID to mean "absent" / "use default" rather than "create a
        // dangling reference".
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
            if let uuid, !uuid.isZero, !allEntries.contains(uuid) {
                results.append(.warning("\(nodePath) points to an Entry that does not exist: \(uuid.uuidString)"))
            }
        }

        func validateCustomIconExists(_ uuid: UUID?, nodePath: String) {
            // XSD: "If non-zero, it overrides IconID." Zero is the documented
            // sentinel for "no custom icon, fall back to IconID".
            if let uuid, !uuid.isZero, !allCustomIcons.contains(uuid) {
                results.append(.warning("\(nodePath) references a non existing Custom Icon: \(uuid.uuidString)"))
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

            validateCustomIconExists(group.customIconUUID, nodePath: "Group[\(group.uuid.uuidString)].CustomIconUUID")
            validateEntryExists(group.lastTopVisibleEntry, nodePath: "Group[\(group.uuid.uuidString)].LastTopVisibleEntry")
            validateGroupExists(group.previousParentGroup, nodePath: "Group[\(group.uuid.uuidString)].PreviousParentGroup")
        }

        visitEntries(in: root.group) { entry in
            results += entry.validate()

            validateCustomIconExists(entry.customIconUUID, nodePath: "Entry[\(entry.uuid.uuidString)].CustomIconUUID")
            validateGroupExists(entry.previousParentGroup, nodePath: "Entry[\(entry.uuid.uuidString)].PreviousParentGroup")
        }

        return results
    }
}
