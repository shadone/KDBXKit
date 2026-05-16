//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// In-place edits over the immutable-by-value `KDBX` tree. Every mutating
/// command (`entry add`, `entry mv`, `group rm`, …) walks the tree by UUID
/// and substitutes the target struct via `inout`.
enum TreeMutator {
    // MARK: - Entries

    /// Apply `body` to the entry with the given UUID. Returns true if found.
    @discardableResult
    static func mutateEntry(
        uuid: UUID,
        in db: inout KDBX,
        _ body: (inout KDBX.Entry) -> Void
    ) -> Bool {
        mutateEntry(uuid: uuid, in: &db.root.group, body)
    }

    private static func mutateEntry(
        uuid: UUID,
        in group: inout KDBX.Group,
        _ body: (inout KDBX.Entry) -> Void
    ) -> Bool {
        for i in group.entries.indices where group.entries[i].uuid == uuid {
            body(&group.entries[i])
            return true
        }
        for i in group.groups.indices {
            if mutateEntry(uuid: uuid, in: &group.groups[i], body) {
                return true
            }
        }
        return false
    }

    /// Detach the entry with `uuid` from the tree. Returns the removed entry
    /// and the UUID of the group it lived in.
    static func removeEntry(uuid: UUID, in db: inout KDBX) -> (entry: KDBX.Entry, parentUUID: UUID)? {
        removeEntry(uuid: uuid, in: &db.root.group)
    }

    private static func removeEntry(
        uuid: UUID,
        in group: inout KDBX.Group
    ) -> (entry: KDBX.Entry, parentUUID: UUID)? {
        if let idx = group.entries.firstIndex(where: { $0.uuid == uuid }) {
            let removed = group.entries.remove(at: idx)
            return (removed, group.uuid)
        }
        for i in group.groups.indices {
            if let result = removeEntry(uuid: uuid, in: &group.groups[i]) {
                return result
            }
        }
        return nil
    }

    /// Append `entry` to the entries of the group with `parentUUID`. Returns
    /// true if that group exists.
    @discardableResult
    static func insertEntry(
        _ entry: KDBX.Entry,
        intoGroup parentUUID: UUID,
        in db: inout KDBX
    ) -> Bool {
        mutateGroup(uuid: parentUUID, in: &db) { parent in
            parent.entries.append(entry)
        }
    }

    // MARK: - Groups

    /// Apply `body` to the group with the given UUID (root included).
    @discardableResult
    static func mutateGroup(
        uuid: UUID,
        in db: inout KDBX,
        _ body: (inout KDBX.Group) -> Void
    ) -> Bool {
        if db.root.group.uuid == uuid {
            body(&db.root.group)
            return true
        }
        return mutateGroupRecursive(uuid: uuid, in: &db.root.group, body)
    }

    private static func mutateGroupRecursive(
        uuid: UUID,
        in group: inout KDBX.Group,
        _ body: (inout KDBX.Group) -> Void
    ) -> Bool {
        for i in group.groups.indices {
            if group.groups[i].uuid == uuid {
                body(&group.groups[i])
                return true
            }
            if mutateGroupRecursive(uuid: uuid, in: &group.groups[i], body) {
                return true
            }
        }
        return false
    }

    /// Detach the group with `uuid` from the tree. Cannot remove root.
    static func removeGroup(uuid: UUID, in db: inout KDBX) -> (group: KDBX.Group, parentUUID: UUID)? {
        guard db.root.group.uuid != uuid else { return nil }
        return removeGroup(uuid: uuid, in: &db.root.group)
    }

    private static func removeGroup(
        uuid: UUID,
        in group: inout KDBX.Group
    ) -> (group: KDBX.Group, parentUUID: UUID)? {
        if let idx = group.groups.firstIndex(where: { $0.uuid == uuid }) {
            let removed = group.groups.remove(at: idx)
            return (removed, group.uuid)
        }
        for i in group.groups.indices {
            if let result = removeGroup(uuid: uuid, in: &group.groups[i]) {
                return result
            }
        }
        return nil
    }

    /// Append `group` as a child of the group with `parentUUID`.
    @discardableResult
    static func insertGroup(
        _ group: KDBX.Group,
        intoGroup parentUUID: UUID,
        in db: inout KDBX
    ) -> Bool {
        mutateGroup(uuid: parentUUID, in: &db) { parent in
            parent.groups.append(group)
        }
    }

    // MARK: - Read-only lookup

    static func findGroup(uuid: UUID, in group: KDBX.Group) -> KDBX.Group? {
        if group.uuid == uuid { return group }
        for child in group.groups {
            if let found = findGroup(uuid: uuid, in: child) { return found }
        }
        return nil
    }

    /// True if `descendant` is anywhere inside the subtree rooted at `ancestor`
    /// (including `ancestor` itself).
    static func isDescendant(_ descendant: UUID, of ancestor: UUID, in db: KDBX) -> Bool {
        guard let anc = findGroup(uuid: ancestor, in: db.root.group) else { return false }
        return subtreeContains(uuid: descendant, in: anc)
    }

    private static func subtreeContains(uuid: UUID, in group: KDBX.Group) -> Bool {
        if group.uuid == uuid { return true }
        for child in group.groups where subtreeContains(uuid: uuid, in: child) {
            return true
        }
        return false
    }

    // MARK: - Times

    /// Stamp `lastModificationTime`. Initializes Times with `creationTime`
    /// when the entry/group had none.
    static func bumpModified(_ times: inout KDBX.Times?, now: Date) {
        var t = times ?? KDBX.Times(creationTime: now)
        t.lastModificationTime = now
        times = t
    }

    /// Stamp both `lastModificationTime` and `locationChanged` — used by
    /// every move/restore operation.
    static func bumpMoved(_ times: inout KDBX.Times?, now: Date) {
        var t = times ?? KDBX.Times(creationTime: now)
        t.lastModificationTime = now
        t.locationChanged = now
        times = t
    }
}

extension UUID {
    var isZeroUUID: Bool {
        self == UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    }
}
