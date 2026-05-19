//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

/// KDBX 3.x stores binaries inline in the XML body under
/// `<Meta><Binaries>`, not in an inner-header pool. The read pipeline
/// harvests them into a synthesized ``InnerHeader.binaryContent`` so
/// downstream code (entry-side `<Value Ref="N"/>` resolution, the
/// writer's binary serializer) stays uniform across formats.
///
/// `kpxc-kdbx31-attachments.kdbx` is a stock KeePassXC 3.1 vault with
/// one entry and two attachments:
///   - `note.txt`: 17 bytes of UTF-8 text (compressible — exercises the
///     inline-pool `Compressed="True"` gunzip path)
///   - `blob.bin`: 8 KB of random bytes (incompressible — exercises the
///     uncompressed path, modulo what KeePassXC's heuristic chooses)
///
/// The fixture was produced with `keepassxc-cli`:
///   - `db-create kpxc-kdbx31-attachments.kdbx --set-password` (password "test")
///   - `add -u alice --url https://example.com / /WithAttach`
///   - `edit -p / /WithAttach` (password "secret123")
///   - `attachment-import / /WithAttach note.txt /tmp/note.txt`
///   - `attachment-import / /WithAttach blob.bin /tmp/blob.bin`
@Suite("KDBX 3.1 inline binary pool")
struct KDBX31BinariesTests {
    private static let fixturePassword = "test"

    private static func openFixture() throws -> KDBXContent {
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-attachments", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        return try KDBXReader.parse(data, unlockData: .init(masterPassword: fixturePassword))
    }

    /// SHA-256 of the bytes originally fed to `keepassxc-cli
    /// attachment-import`. The fixture's binary pool must serve back
    /// these exact bytes; hashing avoids carrying 8 KB of hex around
    /// while still pinning byte content.
    private static let noteSHA256 = "26d9cff76d73a4c3c65cb6e477745d14dda74db77b471fa7bdf378ecd403ce72"
    private static let blobSHA256 = "e73d34ced86f7d8ac3a7802d0684a43f23083215bd2f97c08e62a43bb70b1a60"
    private static let noteSize = 17
    private static let blobSize = 8192

    private static func hexSHA256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    @Test("Inline `<Meta><Binaries>` pool decodes into the synthesized InnerHeader")
    func inlinePool_materializesIntoInnerHeader() throws {
        let content = try Self.openFixture()
        #expect(content.header.formatVersion == .v3_1)

        // Pool must contain both attachments, and InnerHeader is where
        // 4.x callers expect them — the synthesized form mirrors the
        // 4.x shape so downstream code is version-agnostic.
        #expect(content.innerHeader.binaryContent.count == 2)

        // Sizes alone distinguish the two payloads. We don't assume
        // an order — KeePassXC writes IDs starting at 0 in the order
        // imports happened, but the test shouldn't rely on that
        // (sorting by size is enough since 17 ≠ 8192).
        let sizes = content.innerHeader.binaryContent.map(\.data.count).sorted()
        #expect(sizes == [Self.noteSize, Self.blobSize])

        // Byte-content pinned via SHA-256 — proves both the gunzip
        // path (KeePassXC compresses note.txt) and the uncompressed
        // path produce the original bytes.
        let pool = content.innerHeader.binaryContent
        let bySize = Dictionary(uniqueKeysWithValues: pool.map { ($0.data.count, $0) })
        let note = try #require(bySize[Self.noteSize])
        let blob = try #require(bySize[Self.blobSize])
        #expect(Self.hexSHA256(note.data) == Self.noteSHA256)
        #expect(Self.hexSHA256(blob.data) == Self.blobSHA256)
    }

    @Test("Entry-side <Binary Ref> resolves through the synthesized pool")
    func entryBinaryRefs_resolveAgainstPool() throws {
        let content = try Self.openFixture()
        let entry = try #require(content.database.root.group.entries.first)

        // The fixture has two attachments on the WithAttach entry,
        // each a ref into the pool. Inline-stored binaries would
        // appear as `.inline(_, protected:)`, not `.ref(_)`.
        #expect(entry.binaries.count == 2)
        for binary in entry.binaries {
            guard case let .ref(index) = binary.value else {
                Issue.record("Binary \(binary.key) is not a ref — was the fixture regenerated with inline storage?")
                continue
            }
            let resolved = content.innerHeader.binaryContent[Int(index)]
            // Pool-served bytes match by key name. KeePassXC preserves
            // the original filename as the binary key.
            switch binary.key {
            case "note.txt":
                #expect(resolved.data.count == Self.noteSize)
                #expect(Self.hexSHA256(resolved.data) == Self.noteSHA256)
            case "blob.bin":
                #expect(resolved.data.count == Self.blobSize)
                #expect(Self.hexSHA256(resolved.data) == Self.blobSHA256)
            default:
                Issue.record("Unexpected attachment key: \(binary.key)")
            }
        }
    }

    @Test("Round-trip migrates inline binaries into the 4.x inner-header pool")
    func roundTrip_migratesInlineBinariesToInnerHeaderPool() throws {
        // KDBX 4 stores binaries in the inner header, not in
        // <Meta><Binaries>. After migration, the inline XML pool
        // disappears (writer emits 4.x framing) and the bytes move
        // to InnerHeader. The migrated file must still serve the
        // same bytes when re-opened.
        let original = try Self.openFixture()

        let output = OutputStream.toMemory()
        output.open()
        try KDBXWriter(to: output).write(original, unlockData: .init(masterPassword: Self.fixturePassword))
        output.close()
        let migrated = output.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        let roundTripped = try KDBXReader.parse(migrated, unlockData: .init(masterPassword: Self.fixturePassword))
        #expect(roundTripped.header.formatVersion == .v4_1)
        #expect(roundTripped.innerHeader.binaryContent.count == 2)

        // Bytes survive intact through the format migration.
        let sizesAfter = roundTripped.innerHeader.binaryContent.map(\.data.count).sorted()
        #expect(sizesAfter == [Self.noteSize, Self.blobSize])

        let bySize = Dictionary(uniqueKeysWithValues: roundTripped.innerHeader.binaryContent.map { ($0.data.count, $0) })
        #expect(Self.hexSHA256(try #require(bySize[Self.noteSize]).data) == Self.noteSHA256)
        #expect(Self.hexSHA256(try #require(bySize[Self.blobSize]).data) == Self.blobSHA256)

        // Entry refs still resolve after migration — proves the
        // pool indices were preserved across the inline-XML →
        // inner-header relocation.
        let entry = try #require(roundTripped.database.root.group.entries.first)
        #expect(entry.binaries.count == 2)
        for binary in entry.binaries {
            guard case let .ref(index) = binary.value else {
                Issue.record("Binary \(binary.key) lost its ref after migration")
                continue
            }
            #expect(Int(index) < roundTripped.innerHeader.binaryContent.count)
        }
    }

    @Test("3.1 fixture with attachments produces no parser warnings")
    func attachmentFixture_producesNoParserWarnings() throws {
        // Same invariant fixturesProduceNoParserWarnings holds the
        // other real-world fixtures to: any element / attribute we
        // silently drop accumulates here. For the inline-binary path
        // specifically, this catches a future regression where e.g.
        // we stop reading the Protected attribute on <Binary> pool
        // entries.
        let content = try Self.openFixture()
        #expect(content.parserWarnings == [])
    }
}
