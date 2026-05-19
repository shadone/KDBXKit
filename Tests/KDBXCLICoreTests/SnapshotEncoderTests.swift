//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXCLICore
@testable import KDBXKit

@Suite("Snapshot JSON encoders")
struct SnapshotEncoderTests {
    @Test("FieldSnapshot masks protected fields when showSecrets is false")
    func fieldMaskedByDefault() {
        let kv = KDBX.ProtectedString(key: "Password", value: .protectedInMemory("hunter2"))
        let snap = FieldSnapshot(kv, showSecrets: false)
        #expect(snap.masked == true)
        #expect(snap.value == "***")
        #expect(snap.protection == .protectedInMemory)
    }

    @Test("FieldSnapshot reveals when showSecrets is true")
    func fieldRevealed() {
        let kv = KDBX.ProtectedString(key: "Password", value: .protectedInMemory("hunter2"))
        let snap = FieldSnapshot(kv, showSecrets: true)
        #expect(snap.masked == false)
        #expect(snap.value == "hunter2")
    }

    @Test("FieldSnapshot never masks .regular fields, even with showSecrets off")
    func regularNotMasked() {
        let kv = KDBX.ProtectedString(key: "Title", value: .regular("Chase"))
        let snap = FieldSnapshot(kv, showSecrets: false)
        #expect(snap.masked == false)
        #expect(snap.value == "Chase")
    }

    @Test("EntryListSnapshot AND-combines predicates")
    func filterAnd() throws {
        let db = Fixtures.sampleDatabase()
        let ih = InnerHeader(encryptionAlgorithm: .ChaCha20, encryptionKey: SecureBytes(Data(count: 64)), binaryContent: [])
        let onlyChase = try [EntryFilterPredicate.parse("Title=Chase"), EntryFilterPredicate.parse("UserName=alice")]
        let snap = EntryListSnapshot(
            rootGroup: db.root.group,
            innerHeader: ih,
            predicates: onlyChase,
            showSecrets: true
        )
        #expect(snap.entries.count == 1)
        #expect(snap.entries.first?.fields.contains(where: { $0.key == "Title" && $0.value == "Chase" }) == true)
    }

    @Test("EntryListSnapshot with --in subtree only walks that subtree")
    func subtreeRestriction() {
        let db = Fixtures.sampleDatabase()
        let banking = db.root.group.groups.first { $0.name == "Banking" }!
        let ih = InnerHeader(encryptionAlgorithm: .ChaCha20, encryptionKey: SecureBytes(Data(count: 64)), binaryContent: [])
        let snap = EntryListSnapshot(rootGroup: banking, innerHeader: ih, predicates: [], showSecrets: true)
        let titles = Set(snap.entries.compactMap { $0.fields.first { $0.key == "Title" }?.value })
        #expect(titles == Set(["Chase", "Citi"]))
    }

    @Test("ValidationSnapshot.shouldFail honors --level threshold")
    func validationThreshold() {
        let warningsOnly = ValidationSnapshot(issues: [.warning("w")])
        #expect(warningsOnly.shouldFail(at: DB.Validate.Level.error) == false)
        #expect(warningsOnly.shouldFail(at: DB.Validate.Level.warning) == true)

        let withError = ValidationSnapshot(issues: [.error("e"), .warning("w")])
        #expect(withError.shouldFail(at: DB.Validate.Level.error) == true)
        #expect(withError.shouldFail(at: DB.Validate.Level.warning) == true)

        let clean = ValidationSnapshot(issues: [])
        #expect(clean.shouldFail(at: DB.Validate.Level.error) == false)
        #expect(clean.shouldFail(at: DB.Validate.Level.warning) == false)
    }
}
