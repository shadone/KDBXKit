//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("GroupPath.find")
struct GroupPathTests {
    @Test("root-level entry has empty path")
    func rootLevel() {
        let db = Fixtures.sampleDatabase()
        let topLevel = db.root.group.entries.first!
        let path = GroupPath.find(entryUUID: topLevel.uuid, in: db.root.group, prefix: [])
        #expect(path == [])
    }

    @Test("nested entry returns chain of group names")
    func nested() {
        let db = Fixtures.sampleDatabase()
        let chase = db.root.group.groups.first { $0.name == "Banking" }!.entries.first!
        let path = GroupPath.find(entryUUID: chase.uuid, in: db.root.group, prefix: [])
        #expect(path == ["Banking"])
    }

    @Test("unknown entry returns nil")
    func unknown() {
        let db = Fixtures.sampleDatabase()
        let path = GroupPath.find(entryUUID: UUID(), in: db.root.group, prefix: [])
        #expect(path == nil)
    }
}
