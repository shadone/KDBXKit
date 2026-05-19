//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("AddressResolver")
struct AddressResolverTests {
    // MARK: - Entries

    @Test("entry by UUID finds the right entry across the tree")
    func entryByUUID() throws {
        let db = Fixtures.sampleDatabase()
        let chase = db.root.group.groups.first(where: { $0.name == "Banking" })!.entries.first!
        let entry = try AddressResolver.findEntry(.uuid(chase.uuid), in: db)
        #expect(entry.uuid == chase.uuid)
    }

    @Test("entry by nested path resolves through groups")
    func entryByNestedPath() throws {
        let db = Fixtures.sampleDatabase()
        let entry = try AddressResolver.findEntry(.path(PathComponents(raw: "/Banking/Chase")), in: db)
        let title = entry.strings.first { $0.key == "Title" }?.value.revealedString
        #expect(title == "Chase")
    }

    @Test("entry directly under root is reachable by /Title")
    func rootLevelEntry() throws {
        let db = Fixtures.sampleDatabase()
        let entry = try AddressResolver.findEntry(.path(PathComponents(raw: "/topLevel")), in: db)
        let title = entry.strings.first { $0.key == "Title" }?.value.revealedString
        #expect(title == "topLevel")
    }

    @Test("entry not found throws AddressError.entryNotFound")
    func entryNotFound() {
        let db = Fixtures.sampleDatabase()
        #expect(throws: AddressError.self) {
            try AddressResolver.findEntry(.path(PathComponents(raw: "/Nope")), in: db)
        }
    }

    @Test("duplicate path throws AddressError.ambiguous with both UUIDs")
    func ambiguousPath() {
        let db = Fixtures.ambiguousDatabase()
        do {
            _ = try AddressResolver.findEntry(.path(PathComponents(raw: "/Dup")), in: db)
            Issue.record("expected throw")
        } catch let error as AddressError {
            switch error {
            case let .ambiguous(_, matches):
                #expect(matches.count == 2)
            default:
                Issue.record("unexpected: \(error)")
            }
        } catch {
            Issue.record("unexpected: \(error)")
        }
    }

    // MARK: - Groups

    @Test("group by nested path")
    func groupByPath() throws {
        let db = Fixtures.sampleDatabase()
        let group = try AddressResolver.findGroup(.path(PathComponents(raw: "/Banking")), in: db)
        #expect(group.name == "Banking")
    }

    @Test("group by nil address returns root")
    func groupRootViaNil() throws {
        let db = Fixtures.sampleDatabase()
        let group = try AddressResolver.findGroup(nil, in: db)
        #expect(group.uuid == db.root.group.uuid)
    }

    @Test("group by `/` path returns root")
    func groupRootViaSlash() throws {
        let db = Fixtures.sampleDatabase()
        let group = try AddressResolver.findGroup(.path(PathComponents(raw: "/")), in: db)
        #expect(group.uuid == db.root.group.uuid)
    }

    @Test("group not found throws AddressError.groupNotFound")
    func groupNotFound() {
        let db = Fixtures.sampleDatabase()
        #expect(throws: AddressError.self) {
            try AddressResolver.findGroup(.path(PathComponents(raw: "/Nope")), in: db)
        }
    }
}

@Suite("AddressOptions.resolved")
struct AddressOptionsTests {
    @Test("UUID-shaped argument auto-detects as UUID")
    func uuidAutodetect() throws {
        let opts = try AddressOptions.parse(["11111111-1111-1111-1111-111111111111"])
        let resolved = try opts.resolved()
        if case let .uuid(id) = resolved {
            #expect(id.uuidString == "11111111-1111-1111-1111-111111111111")
        } else {
            Issue.record("expected .uuid, got \(resolved)")
        }
    }

    @Test("non-UUID positional becomes path")
    func pathAutodetect() throws {
        let opts = try AddressOptions.parse(["/Banking/Chase"])
        let resolved = try opts.resolved()
        if case let .path(p) = resolved {
            #expect(p.segments == ["Banking", "Chase"])
        } else {
            Issue.record("expected .path, got \(resolved)")
        }
    }

    @Test("explicit --uuid overrides positional")
    func explicitUUIDWins() throws {
        let opts = try AddressOptions.parse([
            "/Banking/Chase",
            "--uuid", "11111111-1111-1111-1111-111111111111",
        ])
        let resolved = try opts.resolved()
        if case .uuid = resolved { /* ok */ } else { Issue.record("expected .uuid") }
    }

    @Test("explicit --uuid with garbage throws invalidUUID")
    func invalidExplicitUUID() throws {
        let opts = try AddressOptions.parse(["--uuid", "not-a-uuid"])
        #expect(throws: AddressError.self) { try opts.resolved() }
    }

    @Test("missing address throws .missing")
    func missing() throws {
        let opts = try AddressOptions.parse([])
        #expect(throws: AddressError.self) { try opts.resolved() }
    }
}
