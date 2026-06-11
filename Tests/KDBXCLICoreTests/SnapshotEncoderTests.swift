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

    @Test("db info output never contains the inner-stream encryption key")
    func dbInfoOmitsInnerStreamKey() throws {
        // The inner random-stream key decrypts every Protected="True"
        // field; combined with `db xml` output, a scrollback capture of
        // `db info` would allow offline decryption of all protected
        // values. No inspection use case needs the raw key.
        let keyBytes = Data(repeating: 0xA7, count: 64)
        let header = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: .AES256CBC,
            compressionAlgorithm: .gzip,
            masterSalt: Data(count: 32),
            encryptionNonce: Data(count: 16),
            kdfParameters: .aes(.init(salt: Data(count: 32), rounds: 1), additional: [:]),
            publicCustomData: [:]
        )
        let snapshot = DBInfoSnapshot(
            header: header,
            unlockState: .unlocked,
            blockSizes: [],
            innerHeader: InnerHeader(
                encryptionAlgorithm: .ChaCha20,
                encryptionKey: SecureBytes(keyBytes),
                binaryContent: []
            ),
            validationIssues: []
        )
        let json = String(data: try JSONEncoder().encode(snapshot), encoding: .utf8)!
        #expect(!json.contains(keyBytes.hexString))
    }

    /// The library intentionally parses vaults with dangling binary refs
    /// (a validation warning, not an error), so the read-only snapshot
    /// types must report them — never trap on the out-of-range subscript.
    @Test("BinarySnapshot reports a dangling ref instead of trapping")
    func binarySnapshotDanglingRef() {
        let ih = InnerHeader(encryptionAlgorithm: .ChaCha20, encryptionKey: SecureBytes(Data(count: 64)), binaryContent: [])
        let snap = BinarySnapshot(
            binary: .init(key: "gone.bin", value: .ref(5)),
            innerHeader: ih
        )
        #expect(snap.dangling)
        #expect(snap.ref == 5)
        #expect(snap.size == 0)
    }

    @Test("AttachmentListSnapshot reports a dangling ref instead of trapping")
    func attachmentListSnapshotDanglingRef() {
        let ih = InnerHeader(encryptionAlgorithm: .ChaCha20, encryptionKey: SecureBytes(Data(count: 64)), binaryContent: [])
        var entry = KDBX.Entry(uuid: UUID())
        entry.binaries = [.init(key: "gone.bin", value: .ref(5))]
        let snap = AttachmentListSnapshot(entry: entry, innerHeader: ih)
        #expect(snap.attachments.first?.dangling == true)
        #expect(snap.attachments.first?.size == 0)
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
