//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit
import Testing
@testable import KDBXCLICore

@Suite("EntryField")
struct EntryFieldTests {
    @Test("setRegular inserts a new plaintext-on-disk field")
    func setRegularInserts() {
        var entry = KDBX.Entry(uuid: UUID())
        EntryField.setRegular("Title", "hello", on: &entry)
        #expect(entry.strings.count == 1)
        let kv = entry.strings[0]
        #expect(kv.key == "Title")
        #expect(kv.value.revealedString == "hello")
        if case .regular = kv.value { } else { Issue.record("expected .regular protection") }
    }

    @Test("setRegular replaces an existing field rather than appending")
    func setRegularReplaces() {
        var entry = KDBX.Entry(uuid: UUID())
        EntryField.setRegular("Title", "v1", on: &entry)
        EntryField.setRegular("Title", "v2", on: &entry)
        #expect(entry.strings.count == 1)
        #expect(entry.strings[0].value.revealedString == "v2")
    }

    @Test("setProtected marks the field as .unprotected so the writer encrypts it")
    func setProtectedEncryption() {
        var entry = KDBX.Entry(uuid: UUID())
        EntryField.setProtected("Password", "secret", on: &entry)
        let kv = entry.strings[0]
        if case .unprotected = kv.value { } else {
            Issue.record("Password should be stored as .unprotected so the writer flags Protected=True")
        }
        #expect(kv.value.revealedString == "secret")
    }

    @Test("setProtected upgrades a previously-regular field in place")
    func setProtectedUpgrades() {
        var entry = KDBX.Entry(uuid: UUID())
        EntryField.setRegular("Token", "old", on: &entry)
        EntryField.setProtected("Token", "new", on: &entry)
        #expect(entry.strings.count == 1)
        if case .unprotected = entry.strings[0].value { } else {
            Issue.record("setProtected should swap the value to .unprotected")
        }
    }

    @Test("remove returns true and drops the field when present")
    func removePresent() {
        var entry = KDBX.Entry(uuid: UUID())
        EntryField.setRegular("Title", "x", on: &entry)
        EntryField.setRegular("URL", "y", on: &entry)
        let removed = EntryField.remove("Title", from: &entry)
        #expect(removed)
        #expect(entry.strings.count == 1)
        #expect(entry.strings[0].key == "URL")
    }

    @Test("remove returns false when no such key exists")
    func removeMissing() {
        var entry = KDBX.Entry(uuid: UUID())
        EntryField.setRegular("URL", "y", on: &entry)
        let removed = EntryField.remove("Notes", from: &entry)
        #expect(!removed)
        #expect(entry.strings.count == 1)
    }

    @Test("standardKeys exposes the five KDBX standard fields")
    func standardKeysComplete() {
        let expected: Set<String> = ["Title", "UserName", "URL", "Notes", "Password"]
        #expect(EntryField.standardKeys == expected)
    }
}

@Suite("EntryFieldAssignment parser")
struct EntryFieldAssignmentTests {
    @Test("parse splits on the first =")
    func parseBasic() throws {
        let a = try EntryFieldAssignment.parse("Phone=555-1234")
        #expect(a.key == "Phone")
        #expect(a.value == "555-1234")
    }

    @Test("parse accepts an empty value (Key=)")
    func parseEmptyValue() throws {
        let a = try EntryFieldAssignment.parse("Phone=")
        #expect(a.key == "Phone")
        #expect(a.value == "")
    }

    @Test("parse keeps subsequent = signs in the value")
    func parseValueWithEquals() throws {
        let a = try EntryFieldAssignment.parse("Note=k=v;k2=v2")
        #expect(a.key == "Note")
        #expect(a.value == "k=v;k2=v2")
    }

    @Test("parse rejects missing =")
    func parseMissingEquals() {
        #expect(throws: EntryFieldAssignmentError.self) {
            _ = try EntryFieldAssignment.parse("noequals")
        }
    }

    @Test("parse rejects empty key (=value)")
    func parseEmptyKey() {
        #expect(throws: EntryFieldAssignmentError.self) {
            _ = try EntryFieldAssignment.parse("=value")
        }
    }
}
