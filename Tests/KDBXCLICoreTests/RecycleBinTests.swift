//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("RecycleBin")
struct RecycleBinTests {
    @Test("find returns nil when Meta.recycleBinUUID is missing")
    func findNil() {
        let db = Fixtures.sampleDatabase()
        #expect(RecycleBin.find(in: db) == nil)
    }

    @Test("find returns nil when recycleBinUUID is the zero UUID")
    func findZeroUUID() {
        var db = Fixtures.sampleDatabase()
        db.meta.recycleBinUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        #expect(RecycleBin.find(in: db) == nil)
    }

    @Test("find returns the bin when Meta points to a real group")
    func findRealBin() {
        let binUUID = UUID()
        let bin = Fixtures.group(name: "Bin", uuid: binUUID, entries: [Fixtures.entry(title: "trashed")])
        let root = Fixtures.group(name: "Root", groups: [bin])
        var meta = KDBX.Meta(generator: "t", databaseName: "T")
        meta.recycleBinUUID = binUUID
        let db = KDBX(meta: meta, root: KDBX.Root(group: root, deletedObjects: []))

        let found = RecycleBin.find(in: db)
        #expect(found?.uuid == binUUID)
    }

    @Test("cleared empties the bin's entries and subgroups, preserves siblings")
    func clearedRetainsRest() {
        let binUUID = UUID()
        let kept = Fixtures.entry(title: "keep")
        let bin = Fixtures.group(
            name: "Bin",
            uuid: binUUID,
            entries: [Fixtures.entry(title: "trash1"), Fixtures.entry(title: "trash2")],
            groups: [Fixtures.group(name: "TrashSubgroup", entries: [Fixtures.entry(title: "trash3")])]
        )
        let root = Fixtures.group(name: "Root", entries: [kept], groups: [bin])
        let meta = KDBX.Meta(generator: "t", databaseName: "T")
        let db = KDBX(meta: meta, root: KDBX.Root(group: root, deletedObjects: []))

        let after = RecycleBin.cleared(in: db, binUUID: binUUID)
        let afterBin = RecycleBin.findGroup(uuid: binUUID, in: after.root.group)!
        #expect(afterBin.entries.isEmpty)
        #expect(afterBin.groups.isEmpty)
        // Siblings untouched.
        #expect(after.root.group.entries.count == 1)
        #expect(after.root.group.entries.first?.uuid == kept.uuid)
    }

    @Test("collectUUIDs walks every entry and subgroup")
    func collectAllIDs() {
        let entry1 = Fixtures.entry(title: "e1")
        let entry2 = Fixtures.entry(title: "e2")
        let entry3 = Fixtures.entry(title: "e3")
        let sub = Fixtures.group(name: "sub", entries: [entry3])
        let bin = Fixtures.group(name: "Bin", entries: [entry1, entry2], groups: [sub])

        var ids: [UUID] = []
        RecycleBin.collectUUIDs(in: bin, into: &ids)

        let expected = Set([entry1.uuid, entry2.uuid, entry3.uuid, sub.uuid])
        #expect(Set(ids) == expected)
    }

    @Test("countEntries / countGroups walk recursively")
    func counts() {
        let sub = Fixtures.group(name: "sub", entries: [Fixtures.entry(title: "e3")])
        let bin = Fixtures.group(
            name: "Bin",
            entries: [Fixtures.entry(title: "e1"), Fixtures.entry(title: "e2")],
            groups: [sub]
        )
        #expect(RecycleBin.countEntries(in: bin) == 3)
        #expect(RecycleBin.countGroups(in: bin) == 1)
    }
}
