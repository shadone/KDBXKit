//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBX.validate — structural checks")
struct ValidationTests {
    @Test("A freshly built empty vault validates clean")
    func freshVaultClean() {
        let content = KDBXContent.makeEmpty(databaseName: "Clean")
        let failures = content.database.validate()
        #expect(failures.isEmpty, "Unexpected validation failures: \(failures)")
    }

    @Test("Duplicate group UUIDs are reported")
    func duplicateGroupUUIDs() {
        let duplicateID = UUID()
        let rootGroup = KDBX.Group(
            uuid: duplicateID,
            name: "Root",
            isExpanded: true,
            groups: [
                KDBX.Group(uuid: duplicateID, name: "Child"),
            ]
        )
        let database = KDBX(
            meta: KDBX.Meta(generator: "Test"),
            root: KDBX.Root(group: rootGroup, deletedObjects: [])
        )

        let failures = database.validate()
        #expect(!failures.isEmpty)
        let mentionsDuplicate = failures.contains { failure in
            failure.message.contains("UUID") && failure.message.contains(duplicateID.uuidString)
        }
        #expect(mentionsDuplicate)
    }

    @Test("Recycle bin UUID pointing at a non-existent group is reported")
    func danglingRecycleBinUUID() {
        let ghostUUID = UUID()
        let meta = KDBX.Meta(
            generator: "Test",
            recycleBinUUID: ghostUUID
        )
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true)
        let database = KDBX(meta: meta, root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        let mentionsRecycleBin = failures.contains { failure in
            failure.message.contains("RecycleBinUUID")
                && failure.message.contains(ghostUUID.uuidString)
        }
        #expect(mentionsRecycleBin)
    }

    @Test("Entry UUID colliding with a group UUID is reported")
    func entryGroupUUIDCollision() {
        let sharedID = UUID()
        let entry = KDBX.Entry(uuid: sharedID)
        let rootGroup = KDBX.Group(
            uuid: sharedID,
            name: "Root",
            isExpanded: true,
            entries: [entry]
        )
        let database = KDBX(
            meta: KDBX.Meta(generator: "Test"),
            root: KDBX.Root(group: rootGroup, deletedObjects: [])
        )

        let failures = database.validate()
        let mentionsCollision = failures.contains { failure in
            failure.message.contains("Entries/Groups use the same UUID")
        }
        #expect(mentionsCollision)
    }

    // MARK: Zero UUID semantics

    //
    // Per the KDBX 4.1 XSD and KeePass conventions, the zero UUID acts as
    // a "no reference" sentinel for most reference fields (CustomIconUUID,
    // PreviousParentGroup, LastTopVisibleEntry, etc.). It must not be
    // reported as a dangling reference.

    private static let zeroUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    @Test("Zero CustomIconUUID on a Group is not flagged")
    func zeroCustomIconUUIDOnGroup_silent() {
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", customIconUUID: Self.zeroUUID, isExpanded: true)
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(!failures.contains { $0.message.contains("CustomIcon") })
    }

    @Test("Zero CustomIconUUID on an Entry is not flagged")
    func zeroCustomIconUUIDOnEntry_silent() {
        let entry = KDBX.Entry(uuid: UUID(), customIconUUID: Self.zeroUUID)
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true, entries: [entry])
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(!failures.contains { $0.message.contains("CustomIcon") })
    }

    @Test("Non-zero dangling CustomIconUUID is still flagged")
    func danglingCustomIconUUID_warns() {
        let ghost = UUID()
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", customIconUUID: ghost, isExpanded: true)
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(failures.contains { $0.message.contains("CustomIcon") && $0.message.contains(ghost.uuidString) })
    }

    @Test("Zero PreviousParentGroup on a Group is not flagged")
    func zeroPreviousParentGroupOnGroup_silent() {
        let child = KDBX.Group(uuid: UUID(), name: "Child", previousParentGroup: Self.zeroUUID)
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true, groups: [child])
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(!failures.contains { $0.message.contains("PreviousParentGroup") })
    }

    @Test("Zero PreviousParentGroup on an Entry is not flagged")
    func zeroPreviousParentGroupOnEntry_silent() {
        let entry = KDBX.Entry(uuid: UUID(), previousParentGroup: Self.zeroUUID)
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true, entries: [entry])
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(!failures.contains { $0.message.contains("PreviousParentGroup") })
    }

    @Test("Zero LastTopVisibleEntry on a Group is not flagged")
    func zeroLastTopVisibleEntry_silent() {
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true, lastTopVisibleEntry: Self.zeroUUID)
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(!failures.contains { $0.message.contains("LastTopVisibleEntry") })
    }

    @Test("PreviousParentGroup pointing forward to a later sibling is not flagged")
    func forwardPreviousParentGroup_silent() {
        // Reproduces the old in-walk bug: child A's previousParentGroup pointed at
        // sibling B, which only enters `allGroups` later in the traversal. The
        // post-walk-only check used here must accept this.
        let siblingB = UUID()
        let childA = KDBX.Group(uuid: UUID(), name: "A", previousParentGroup: siblingB)
        let childB = KDBX.Group(uuid: siblingB, name: "B")
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true, groups: [childA, childB])
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(!failures.contains { $0.message.contains("PreviousParentGroup") })
    }

    @Test("Non-zero dangling PreviousParentGroup is still flagged")
    func danglingPreviousParentGroup_warns() {
        let ghost = UUID()
        let entry = KDBX.Entry(uuid: UUID(), previousParentGroup: ghost)
        let rootGroup = KDBX.Group(uuid: UUID(), name: "Root", isExpanded: true, entries: [entry])
        let database = KDBX(meta: KDBX.Meta(generator: "Test"), root: KDBX.Root(group: rootGroup, deletedObjects: []))

        let failures = database.validate()
        #expect(failures.contains { $0.message.contains("PreviousParentGroup") && $0.message.contains(ghost.uuidString) })
    }

    @Test("A binary Ref beyond the pool on a live entry is flagged")
    func danglingLiveBinaryRef_warns() {
        // makeEmpty has an empty binary pool, so any ref is dangling.
        var content = KDBXContent.makeEmpty(databaseName: "Live")
        let live = KDBX.Entry(
            uuid: UUID(),
            binaries: [KDBX.ProtectedBinary(key: "notes.txt", value: .ref(5))]
        )
        content.database.root.group.entries.append(live)

        let failures = content.validate()
        #expect(
            failures.contains { $0.message.contains("Ref=5") && $0.message.contains("non-existing Binary") },
            "live dangling ref not reported: \(failures.map(\.message))"
        )
    }

    @Test("A binary Ref beyond the pool in a history snapshot is flagged")
    func danglingHistoryBinaryRef_warns() {
        // Regression: the validator used to ignore history binaries, so
        // a corrupt save that left a dangling ref only in a history
        // snapshot would slip through. History refs share the same pool.
        var content = KDBXContent.makeEmpty(databaseName: "Hist")
        let historic = KDBX.Entry(
            uuid: UUID(),
            binaries: [KDBX.ProtectedBinary(key: "notes.txt", value: .ref(0))]
        )
        let live = KDBX.Entry(uuid: UUID(), history: [historic])
        content.database.root.group.entries.append(live)

        let failures = content.validate()
        #expect(
            failures.contains { $0.message.contains("History") && $0.message.contains("Ref=0") },
            "history dangling ref not reported: \(failures.map(\.message))"
        )
    }
}
