//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("TreeMutator")
struct TreeMutatorTests {
    // MARK: - mutateEntry

    @Test("mutateEntry applies body to matching entry and returns true")
    func mutateEntryFound() {
        var db = Fixtures.sampleDatabase()
        let chase = db.root.group.groups.first(where: { $0.name == "Banking" })!.entries.first!
        let found = TreeMutator.mutateEntry(uuid: chase.uuid, in: &db) { entry in
            entry.iconID = 99
        }
        #expect(found)

        let after = db.root.group.groups.first(where: { $0.name == "Banking" })!.entries.first!
        #expect(after.iconID == 99)
        #expect(after.uuid == chase.uuid)
    }

    @Test("mutateEntry returns false and is a no-op when UUID is absent")
    func mutateEntryMissing() {
        var db = Fixtures.sampleDatabase()
        let before = db
        let found = TreeMutator.mutateEntry(uuid: UUID(), in: &db) { e in e.iconID = 99 }
        #expect(!found)
        #expect(db == before)
    }

    @Test("mutateEntry finds an entry nested deep in the tree")
    func mutateEntryNested() {
        let leafUUID = UUID()
        let leaf = Fixtures.entry(title: "deep", uuid: leafUUID)
        let inner = Fixtures.group(name: "inner", entries: [leaf])
        let outer = Fixtures.group(name: "outer", groups: [inner])
        let root = Fixtures.group(name: "Root", groups: [outer])
        var db = KDBX(meta: KDBX.Meta(generator: "t"), root: KDBX.Root(group: root, deletedObjects: []))

        let found = TreeMutator.mutateEntry(uuid: leafUUID, in: &db) { e in
            e.iconID = 42
        }
        #expect(found)
        #expect(db.root.group.groups[0].groups[0].entries[0].iconID == 42)
    }

    // MARK: - mutateGroup

    @Test("mutateGroup includes the root group itself")
    func mutateGroupRoot() {
        var db = Fixtures.sampleDatabase()
        let rootUUID = db.root.group.uuid
        let found = TreeMutator.mutateGroup(uuid: rootUUID, in: &db) { group in
            group.notes = "edited"
        }
        #expect(found)
        #expect(db.root.group.notes == "edited")
    }

    @Test("mutateGroup descends into nested groups")
    func mutateGroupNested() {
        var db = Fixtures.sampleDatabase()
        let bankingUUID = db.root.group.groups.first(where: { $0.name == "Banking" })!.uuid
        let found = TreeMutator.mutateGroup(uuid: bankingUUID, in: &db) { g in
            g.name = "Renamed"
        }
        #expect(found)
        #expect(db.root.group.groups.contains(where: { $0.name == "Renamed" }))
    }

    // MARK: - removeEntry

    @Test("removeEntry returns the removed entry and its parent UUID")
    func removeEntryReturnsParent() {
        var db = Fixtures.sampleDatabase()
        let banking = db.root.group.groups.first(where: { $0.name == "Banking" })!
        let chase = banking.entries.first!

        let result = TreeMutator.removeEntry(uuid: chase.uuid, in: &db)
        #expect(result?.entry.uuid == chase.uuid)
        #expect(result?.parentUUID == banking.uuid)

        let after = db.root.group.groups.first(where: { $0.name == "Banking" })!
        #expect(!after.entries.contains(where: { $0.uuid == chase.uuid }))
    }

    @Test("removeEntry returns nil when the UUID isn't anywhere in the tree")
    func removeEntryMissing() {
        var db = Fixtures.sampleDatabase()
        let before = db
        let result = TreeMutator.removeEntry(uuid: UUID(), in: &db)
        #expect(result == nil)
        #expect(db == before)
    }

    @Test("removeEntry works for root-level entries")
    func removeEntryAtRoot() {
        var db = Fixtures.sampleDatabase()
        let topLevel = db.root.group.entries.first!
        let result = TreeMutator.removeEntry(uuid: topLevel.uuid, in: &db)
        #expect(result?.parentUUID == db.root.group.uuid)
        #expect(db.root.group.entries.isEmpty)
    }

    // MARK: - removeGroup

    @Test("removeGroup detaches a child group and returns parent UUID")
    func removeGroupChild() {
        var db = Fixtures.sampleDatabase()
        let rootUUID = db.root.group.uuid
        let banking = db.root.group.groups.first(where: { $0.name == "Banking" })!

        let result = TreeMutator.removeGroup(uuid: banking.uuid, in: &db)
        #expect(result?.group.uuid == banking.uuid)
        #expect(result?.parentUUID == rootUUID)
        #expect(!db.root.group.groups.contains(where: { $0.uuid == banking.uuid }))
    }

    @Test("removeGroup refuses to remove the root group")
    func removeGroupRefusesRoot() {
        var db = Fixtures.sampleDatabase()
        let rootUUID = db.root.group.uuid
        let before = db
        let result = TreeMutator.removeGroup(uuid: rootUUID, in: &db)
        #expect(result == nil)
        #expect(db == before)
    }

    @Test("removeGroup returns nil for an unknown UUID")
    func removeGroupMissing() {
        var db = Fixtures.sampleDatabase()
        let before = db
        let result = TreeMutator.removeGroup(uuid: UUID(), in: &db)
        #expect(result == nil)
        #expect(db == before)
    }

    // MARK: - insert

    @Test("insertEntry appends to the parent's entries when parent exists")
    func insertEntryAppends() {
        var db = Fixtures.sampleDatabase()
        let banking = db.root.group.groups.first(where: { $0.name == "Banking" })!
        let before = banking.entries.count
        let added = Fixtures.entry(title: "Amex")
        let inserted = TreeMutator.insertEntry(added, intoGroup: banking.uuid, in: &db)
        #expect(inserted)
        let after = db.root.group.groups.first(where: { $0.name == "Banking" })!
        #expect(after.entries.count == before + 1)
        #expect(after.entries.last?.uuid == added.uuid)
    }

    @Test("insertEntry returns false when the parent UUID is unknown")
    func insertEntryMissingParent() {
        var db = Fixtures.sampleDatabase()
        let before = db
        let inserted = TreeMutator.insertEntry(Fixtures.entry(title: "x"), intoGroup: UUID(), in: &db)
        #expect(!inserted)
        #expect(db == before)
    }

    @Test("insertGroup appends to the parent group's subgroups")
    func insertGroupAppends() {
        var db = Fixtures.sampleDatabase()
        let rootUUID = db.root.group.uuid
        let before = db.root.group.groups.count
        let added = Fixtures.group(name: "New")
        let inserted = TreeMutator.insertGroup(added, intoGroup: rootUUID, in: &db)
        #expect(inserted)
        #expect(db.root.group.groups.count == before + 1)
        #expect(db.root.group.groups.last?.uuid == added.uuid)
    }

    // MARK: - isDescendant

    @Test("isDescendant: group is its own descendant")
    func descendantSelf() {
        let db = Fixtures.sampleDatabase()
        let banking = db.root.group.groups.first(where: { $0.name == "Banking" })!
        #expect(TreeMutator.isDescendant(banking.uuid, of: banking.uuid, in: db))
    }

    @Test("isDescendant: child is a descendant of parent")
    func descendantChild() {
        let leafUUID = UUID()
        let leaf = Fixtures.group(name: "leaf", uuid: leafUUID)
        let mid = Fixtures.group(name: "mid", groups: [leaf])
        let outer = Fixtures.group(name: "outer", groups: [mid])
        let root = Fixtures.group(name: "Root", groups: [outer])
        let db = KDBX(meta: KDBX.Meta(generator: "t"), root: KDBX.Root(group: root, deletedObjects: []))
        #expect(TreeMutator.isDescendant(leafUUID, of: outer.uuid, in: db))
    }

    @Test("isDescendant: siblings are not descendants of each other")
    func descendantSiblings() {
        let db = Fixtures.sampleDatabase()
        let banking = db.root.group.groups.first(where: { $0.name == "Banking" })!
        let social = db.root.group.groups.first(where: { $0.name == "Social" })!
        #expect(!TreeMutator.isDescendant(banking.uuid, of: social.uuid, in: db))
        #expect(!TreeMutator.isDescendant(social.uuid, of: banking.uuid, in: db))
    }

    @Test("isDescendant: unknown ancestor returns false (not a crash)")
    func descendantUnknownAncestor() {
        let db = Fixtures.sampleDatabase()
        #expect(!TreeMutator.isDescendant(db.root.group.uuid, of: UUID(), in: db))
    }

    // MARK: - findGroup

    @Test("findGroup walks the tree and returns the matching group")
    func findGroupFinds() {
        let db = Fixtures.sampleDatabase()
        let banking = db.root.group.groups.first(where: { $0.name == "Banking" })!
        let found = TreeMutator.findGroup(uuid: banking.uuid, in: db.root.group)
        #expect(found?.uuid == banking.uuid)
    }

    @Test("findGroup returns nil for absent UUID")
    func findGroupMissing() {
        let db = Fixtures.sampleDatabase()
        let found = TreeMutator.findGroup(uuid: UUID(), in: db.root.group)
        #expect(found == nil)
    }

    // MARK: - Times helpers

    @Test("bumpModified sets lastModificationTime and seeds creationTime on a nil Times")
    func bumpModifiedFromNil() {
        var times: KDBX.Times?
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        TreeMutator.bumpModified(&times, now: now)
        #expect(times?.creationTime == now)
        #expect(times?.lastModificationTime == now)
        // bumpModified does NOT touch locationChanged.
        #expect(times?.locationChanged == nil)
    }

    @Test("bumpModified preserves an existing creationTime")
    func bumpModifiedPreservesCreation() {
        let created = Date(timeIntervalSince1970: 1_600_000_000)
        var times: KDBX.Times? = KDBX.Times(creationTime: created)
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        TreeMutator.bumpModified(&times, now: now)
        #expect(times?.creationTime == created)
        #expect(times?.lastModificationTime == now)
    }

    @Test("bumpMoved sets both lastModificationTime and locationChanged")
    func bumpMovedSetsBoth() {
        var times: KDBX.Times?
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        TreeMutator.bumpMoved(&times, now: now)
        #expect(times?.lastModificationTime == now)
        #expect(times?.locationChanged == now)
    }

    // MARK: - isZeroUUID

    @Test("isZeroUUID is true only for the all-zeroes UUID")
    func isZero() {
        let zero = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        #expect(zero.isZeroUUID)
        #expect(!UUID().isZeroUUID)
    }
}
