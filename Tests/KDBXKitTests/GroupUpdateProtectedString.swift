//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Test
func groupUpdateProtectedString() {
    var root = KDBX.Group(
        uuid: UUID(),
        entries: [
            .init(
                uuid: UUID(),
                strings: [
                    .init(key: "root-level-entry", value: .regular("root-level-entry-value")),
                ],
            ),
        ],
        groups: [
            .init(
                uuid: UUID(),
                entries: [
                    .init(
                        uuid: UUID(),
                        strings: [
                            .init(key: "child1", value: .regular("child1-value")),
                        ],
                    ),
                ],
            ),
        ]
    )

    root.updateProtectedString(
        to: .init(key: "new-root", value: .regular("new-root-value")),
        groupPath: [],
        entryIndex: 0,
        historyIndex: nil,
        stringIndex: 0
    )
    #expect(root.entries[0].strings[0].key == "new-root")
    #expect(root.entries[0].strings[0].value == .regular("new-root-value"))

    root.updateProtectedString(
        to: .init(key: "new-child1", value: .regular("new-child1-value")),
        groupPath: [0],
        entryIndex: 0,
        historyIndex: nil,
        stringIndex: 0
    )
    #expect(root.groups[0].entries[0].strings[0].key == "new-child1")
    #expect(root.groups[0].entries[0].strings[0].value == .regular("new-child1-value"))
}
