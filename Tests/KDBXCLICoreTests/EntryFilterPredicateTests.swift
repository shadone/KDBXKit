//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("EntryFilterPredicate")
struct EntryFilterPredicateTests {
    @Test("parses field=substring into lowercased needle")
    func parseOK() throws {
        let p = try EntryFilterPredicate.parse("Title=Chase")
        #expect(p.field == "Title")
        #expect(p.needle == "chase")
    }

    @Test("parses empty needle (matches anywhere)")
    func parseEmptyNeedle() throws {
        let p = try EntryFilterPredicate.parse("Title=")
        #expect(p.field == "Title")
        #expect(p.needle == "")
    }

    @Test("missing = errors")
    func parseMissingEquals() {
        #expect(throws: EntryFilterError.self) {
            _ = try EntryFilterPredicate.parse("Title")
        }
    }

    @Test("empty field errors")
    func parseEmptyField() {
        #expect(throws: EntryFilterError.self) {
            _ = try EntryFilterPredicate.parse("=value")
        }
    }

    @Test("matches via case-insensitive substring")
    func matchCaseInsensitive() throws {
        let entry = Fixtures.entry(title: "Chase", username: "alice")
        let predicate = try EntryFilterPredicate.parse("Title=HAS")
        #expect(predicate.matches(entry))
    }

    @Test("non-matching field returns false")
    func matchFieldMissing() throws {
        let entry = Fixtures.entry(title: "Chase")
        let predicate = try EntryFilterPredicate.parse("URL=example")
        #expect(!predicate.matches(entry))
    }

    @Test("non-matching needle returns false")
    func matchNeedleMissing() throws {
        let entry = Fixtures.entry(title: "Chase")
        let predicate = try EntryFilterPredicate.parse("Title=Citi")
        #expect(!predicate.matches(entry))
    }
}
