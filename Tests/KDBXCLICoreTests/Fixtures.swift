//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Builders for synthetic vault content used by CLI tests. None of these
/// touch disk — they build `KDBX` / `KDBXContent` values directly so tests
/// can exercise resolver, filter, and snapshot logic without round-tripping
/// through the encrypted format.
enum Fixtures {
    static func entry(title: String, username: String = "", password: String = "", uuid: UUID = UUID()) -> KDBX.Entry {
        var strings: [KDBX.ProtectedString] = [
            .init(key: "Title", value: .regular(title)),
        ]
        if !username.isEmpty {
            strings.append(.init(key: "UserName", value: .regular(username)))
        }
        if !password.isEmpty {
            strings.append(.init(key: "Password", value: .protectedInMemory(password)))
        }
        return KDBX.Entry(uuid: uuid, strings: strings)
    }

    static func group(
        name: String,
        uuid: UUID = UUID(),
        entries: [KDBX.Entry] = [],
        groups: [KDBX.Group] = []
    ) -> KDBX.Group {
        KDBX.Group(uuid: uuid, name: name, entries: entries, groups: groups)
    }

    /// Synthetic vault with a small fixed hierarchy:
    ///
    ///     /
    ///     ├── Banking
    ///     │   ├── Chase     (UserName=alice, Password=hunter2)
    ///     │   └── Citi
    ///     ├── Social
    ///     │   └── Twitter   (UserName=bob)
    ///     └── topLevel      (root-level entry)
    static func sampleDatabase() -> KDBX {
        let chase = entry(title: "Chase", username: "alice", password: "hunter2")
        let citi = entry(title: "Citi")
        let twitter = entry(title: "Twitter", username: "bob")
        let topLevel = entry(title: "topLevel")
        let banking = group(name: "Banking", entries: [chase, citi])
        let social = group(name: "Social", entries: [twitter])
        let root = group(name: "Root", entries: [topLevel], groups: [banking, social])
        let meta = KDBX.Meta(generator: "test", databaseName: "Test")
        return KDBX(meta: meta, root: KDBX.Root(group: root, deletedObjects: []))
    }

    /// Database with duplicate titles to exercise ambiguity handling.
    static func ambiguousDatabase() -> KDBX {
        let dup1 = entry(title: "Dup", uuid: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!)
        let dup2 = entry(title: "Dup", uuid: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!)
        let root = group(name: "Root", entries: [dup1, dup2])
        let meta = KDBX.Meta(generator: "test", databaseName: "Test")
        return KDBX(meta: meta, root: KDBX.Root(group: root, deletedObjects: []))
    }
}
