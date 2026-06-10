//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("RecycleBinManager")
struct RecycleBinManagerTests {
    /// Build a KDBXContent around a synthetic database. Header / inner-header
    /// values are placeholders — these tests never serialize.
    private func makeContent(_ db: KDBX) -> KDBXContent {
        let header = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: .ChaCha20,
            compressionAlgorithm: .gzip,
            masterSalt: Data(count: 32),
            encryptionNonce: Data(count: 12),
            kdfParameters: .argon2idDefault(),
            publicCustomData: [:]
        )
        let inner = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: Data(count: 64),
            binaryContent: []
        )
        return KDBXContent(database: db, header: header, innerHeader: inner)
    }

    @Test("ensureBin returns nil when recycleBinEnabled is explicitly false")
    func disabledOptOut() {
        var db = Fixtures.sampleDatabase()
        db.meta.recycleBinEnabled = false
        var content = makeContent(db)
        let before = content.database

        let result = RecycleBinManager.ensureBin(in: &content, now: Date())
        #expect(result == nil)
        // Vault must not be mutated when the user has opted out.
        #expect(content.database == before)
    }

    @Test("ensureBin creates a fresh bin when the UUID is missing and stamps Meta")
    func createsWhenMissing() {
        var content = makeContent(Fixtures.sampleDatabase())
        // sampleDatabase doesn't set recycleBinUUID.
        #expect(content.database.meta.recycleBinUUID == nil)

        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let before = Date()
        let result = RecycleBinManager.ensureBin(in: &content, now: now)
        let after = Date()
        #expect(result != nil)

        let binID = try! #require(result)
        #expect(content.database.meta.recycleBinUUID == binID)
        // `recycleBinChanged` is stamped by `Meta.recycleBinUUID`'s
        // `didSet` with wall-clock time — not the caller-supplied
        // `now` (which still pins the new bin group's own `Times`).
        // Assert it landed within the call window instead of the
        // exact value.
        let stamped = try! #require(content.database.meta.recycleBinChanged)
        #expect(stamped >= before && stamped <= after)
        // recycleBinEnabled was nil before; the helper opts in.
        #expect(content.database.meta.recycleBinEnabled == true)

        // The newly-created bin lives at root and matches KeePass conventions:
        // icon 43, name "Recycle Bin".
        let bin = try! #require(TreeMutator.findGroup(uuid: binID, in: content.database.root.group))
        #expect(bin.name == "Recycle Bin")
        #expect(bin.iconID == RecycleBinManager.recycleBinIconID)
    }

    @Test("ensureBin creates a fresh bin when the recorded UUID is zero")
    func createsWhenZero() {
        var db = Fixtures.sampleDatabase()
        db.meta.recycleBinUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        var content = makeContent(db)

        let result = RecycleBinManager.ensureBin(in: &content, now: Date())
        let binID = try! #require(result)
        #expect(!binID.isZeroUUID)
        #expect(TreeMutator.findGroup(uuid: binID, in: content.database.root.group) != nil)
    }

    @Test("ensureBin creates a fresh bin when the recorded UUID points to nothing")
    func createsWhenDangling() {
        var db = Fixtures.sampleDatabase()
        let dangling = UUID()
        db.meta.recycleBinUUID = dangling
        var content = makeContent(db)

        let result = RecycleBinManager.ensureBin(in: &content, now: Date())
        let binID = try! #require(result)
        #expect(binID != dangling)
        #expect(TreeMutator.findGroup(uuid: binID, in: content.database.root.group) != nil)
    }

    @Test("ensureBin reuses an existing bin and does not mutate the tree")
    func reusesExisting() {
        let binUUID = UUID()
        let bin = Fixtures.group(name: "Existing Bin", uuid: binUUID)
        var root = Fixtures.sampleDatabase().root.group
        root.groups.append(bin)
        var db = KDBX(
            meta: KDBX.Meta(generator: "t", recycleBinUUID: binUUID),
            root: KDBX.Root(group: root, deletedObjects: [])
        )
        db.meta.recycleBinEnabled = true
        var content = makeContent(db)
        let before = content.database

        let result = RecycleBinManager.ensureBin(in: &content, now: Date())
        #expect(result == binUUID)
        #expect(content.database == before)
    }

    @Test("ensureBin preserves an explicit recycleBinEnabled=true")
    func preservesEnabledTrue() {
        var db = Fixtures.sampleDatabase()
        db.meta.recycleBinEnabled = true
        var content = makeContent(db)

        _ = RecycleBinManager.ensureBin(in: &content, now: Date())
        #expect(content.database.meta.recycleBinEnabled == true)
    }
}
