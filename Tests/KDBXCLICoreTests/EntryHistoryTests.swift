//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("EntryHistory")
struct EntryHistoryTests {
    private func entryWithTitle(_ title: String) -> KDBX.Entry {
        var e = KDBX.Entry(uuid: UUID())
        EntryField.setRegular("Title", title, on: &e)
        return e
    }

    @Test("snapshot appends a copy of the live entry to its history list")
    func snapshotAppends() {
        var entry = entryWithTitle("v1")
        let meta = KDBX.Meta(generator: "t")
        EntryHistory.snapshot(&entry, meta: meta)
        #expect(entry.history.count == 1)
        #expect(entry.history[0].strings.first(where: { $0.key == "Title" })?.value.revealedString == "v1")
    }

    @Test("snapshot strips the nested history list so growth stays linear")
    func snapshotStripsNested() {
        var entry = entryWithTitle("v2")
        // Pretend a prior snapshot is already attached.
        entry.history = [entryWithTitle("v1")]

        let meta = KDBX.Meta(generator: "t")
        EntryHistory.snapshot(&entry, meta: meta)

        #expect(entry.history.count == 2)
        // The newly-pushed snapshot must not carry the previous history forward.
        #expect(entry.history.last?.history.isEmpty == true)
    }

    @Test("snapshot respects Meta.historyMaxItems and drops the oldest")
    func snapshotTrimsByMaxItems() {
        var entry = entryWithTitle("live")
        // Pretend we already have 3 prior versions.
        entry.history = [entryWithTitle("v1"), entryWithTitle("v2"), entryWithTitle("v3")]

        var meta = KDBX.Meta(generator: "t")
        meta.historyMaxItems = .value(3)

        // Adding "live" as the 4th would overflow the cap of 3 — the oldest
        // ("v1") gets dropped, leaving v2/v3/live.
        EntryHistory.snapshot(&entry, meta: meta)

        #expect(entry.history.count == 3)
        let titles = entry.history.map { $0.strings.first(where: { $0.key == "Title" })?.value.revealedString }
        #expect(titles == ["v2", "v3", "live"])
    }

    @Test("snapshot leaves history intact when historyMaxItems is .unlimited")
    func snapshotUnlimited() {
        var entry = entryWithTitle("live")
        entry.history = (1...5).map { entryWithTitle("v\($0)") }
        var meta = KDBX.Meta(generator: "t")
        meta.historyMaxItems = .unlimited
        EntryHistory.snapshot(&entry, meta: meta)
        #expect(entry.history.count == 6)
    }

    @Test("snapshot leaves history intact when historyMaxItems is nil (no policy set)")
    func snapshotNoPolicy() {
        var entry = entryWithTitle("live")
        entry.history = (1...20).map { entryWithTitle("v\($0)") }
        let meta = KDBX.Meta(generator: "t")
        #expect(meta.historyMaxItems == nil)
        EntryHistory.snapshot(&entry, meta: meta)
        #expect(entry.history.count == 21)
    }

    @Test("trim is a no-op when count is already below the cap")
    func trimNoop() {
        var history = (1...3).map { entryWithTitle("v\($0)") }
        let dropped = EntryHistory.trim(&history, against: .value(5))
        #expect(dropped == 0)
        #expect(history.count == 3)
    }

    @Test("trim against .value(0) wipes history entirely")
    func trimToZero() {
        var history = (1...3).map { entryWithTitle("v\($0)") }
        let dropped = EntryHistory.trim(&history, against: .value(0))
        #expect(dropped == 3)
        #expect(history.isEmpty)
    }

    @Test("trim drops from the front (oldest), preserving the newest items")
    func trimDropsOldest() {
        var history = (1...5).map { entryWithTitle("v\($0)") }
        let dropped = EntryHistory.trim(&history, against: .value(2))
        #expect(dropped == 3)
        let titles = history.map { $0.strings.first(where: { $0.key == "Title" })?.value.revealedString }
        #expect(titles == ["v4", "v5"])
    }
}
