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
        let content = KDBXContent.makeEmpty(databaseName: "Clean", kdf: .fast)
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
}
