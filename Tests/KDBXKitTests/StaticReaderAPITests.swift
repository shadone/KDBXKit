//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBXReader static API")
struct StaticReaderAPITests {

    @Test("parse(data, unlockData:) returns content in one call")
    func staticParse() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        #expect(content.header.formatVersion == .v4_0)
        #expect(content.database.meta.databaseName != nil)
    }

    @Test("parseHeader(data) inspects without credentials")
    func staticParseHeader() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        let header = try KDBXReader.parseHeader(data)
        #expect(header.formatVersion == .v4_0)
        #expect(header.encryptionAlgorithm == .AES256CBC)
        #expect(header.compressionAlgorithm == .gzip)
        // Public custom data should be empty for these fixtures.
        #expect(header.publicCustomData.isEmpty)
    }

    @Test("KDBX 3.1 file opens, exposes a legacy-format migration notice, and decrypts protected fields")
    func kdbx31_opensWithMigrationNotice() throws {
        // `keepassxc-cli db-create` writes KDBX 3.1 by default. The 3.x
        // on-disk shape differs from 4.x in several places (UInt16
        // header field lengths, no SHA/HMAC trailer, hashed block
        // stream, inline <Meta><Binaries>, ISO-8601 dates), so the
        // read pipeline takes a separate path. The fixture is a stock
        // KeePassXC db-create output edited to contain one entry with
        // a protected password — covers the Salsa20 inner-stream
        // keystream end-to-end.
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))

        // On-disk version preserved so callers can show a precise
        // upgrade message ("KDBX 3.1 → 4.1").
        #expect(content.header.formatVersion == .v3_1)
        #expect(content.legacyFormatNotice == .willMigrate(from: .v3_1))

        // The inner header is synthesized by ``Header3xReader``'s
        // sibling pipeline: the 3.x ProtectedStreamKey is migrated to
        // the same channel the 4.x reader fills, so keystream
        // consumers don't have to special-case format version.
        #expect(content.innerHeader.encryptionAlgorithm == .Salsa20)

        // Real-world fixtures parse without dropping unknown elements
        // — same invariant we hold 4.x fixtures to.
        #expect(content.parserWarnings == [])

        // ISO-8601 dates flowed through `parseDate(.iso8601)`; one
        // entry has a meaningful timestamp.
        let entry = try #require(content.database.root.group.entries.first)
        #expect(entry.times?.creationTime != nil)

        // Salsa20 keystream produced the right plaintext for the
        // password field — the canonical correctness signal for the
        // 3.x inner-cipher path.
        let password = try #require(entry.strings.first(where: { $0.key == "Password" }))
        let revealed = password.value.bytes.withRevealedString { $0 }
        #expect(revealed == "secret123")
    }

    @Test("Wrong password on a KDBX 3.1 file surfaces .wrongCredentials via StreamStartBytes")
    func kdbx31_wrongPasswordSurfacesStructuredError() throws {
        // KDBX 3.x has no header HMAC; the wrong-credentials signal is
        // the constant-time compare of the first 32 plaintext bytes
        // after AES-CBC decrypt against the cleartext-header
        // StreamStartBytes value. A wrong key produces structurally
        // random plaintext that almost-never collides with the
        // sentinel, so the right credential-rejection path is
        // .wrongCredentials — not .corruptedXML / .corruptedHeader
        // (which would surface only if the bad plaintext happened to
        // pass the StreamStartBytes check and then fail downstream).
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "wrong"))
        }
    }

    @Test("KDBX 3.1 file round-trips through the writer as KDBX 4.1")
    func kdbx31_writerMigratesToV4_1() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        let original = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))
        #expect(original.header.formatVersion == .v3_1)

        let output = OutputStream.toMemory()
        output.open()
        let writer = KDBXWriter(to: output)
        try writer.write(original, unlockData: .init(masterPassword: "test"))
        output.close()
        let migrated = output.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // Reopen the migrated bytes — the writer must produce a
        // structurally-valid KDBX 4 file (4.1, per the writer clamp).
        let roundTripped = try KDBXReader.parse(migrated, unlockData: .init(masterPassword: "test"))
        #expect(roundTripped.header.formatVersion == .v4_1)

        // After migration the notice is gone — the on-disk file is
        // 4.x and no further upgrade is needed.
        #expect(roundTripped.legacyFormatNotice == nil)

        // Content survives the migration: the database tree, entry
        // count, and protected password all round-trip.
        let originalEntry = try #require(original.database.root.group.entries.first)
        let migratedEntry = try #require(roundTripped.database.root.group.entries.first)
        #expect(originalEntry.uuid == migratedEntry.uuid)

        let originalPassword = try #require(originalEntry.strings.first(where: { $0.key == "Password" }))
        let migratedPassword = try #require(migratedEntry.strings.first(where: { $0.key == "Password" }))
        let originalRevealed = originalPassword.value.bytes.withRevealedString { $0 }
        let migratedRevealed = migratedPassword.value.bytes.withRevealedString { $0 }
        #expect(originalRevealed == migratedRevealed)
        #expect(migratedRevealed == "secret123")
    }

    @Test("parse with wrong password throws .wrongCredentials")
    func wrongPasswordSurfacesStructuredError() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "wrong"))
        }
    }

    @Test("Lazy open of a KDBX 3.1 file throws unsupportedFormatVersion so callers fall back to eager parse")
    func kdbx31_lazyOpenSurfacesTypedErrorForEagerFallback() throws {
        // The lazy path's contract is "stream binaries on demand from
        // the on-disk pool", which has no analog in 3.x where binaries
        // live inline in XML. We surface a typed error rather than
        // silently materializing everything, so callers know to switch
        // to eager `parse` (and present the migration notice).
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let url = URL(filePath: path)
        do {
            _ = try KDBXReader.openMetadataOnly(from: .file(url), unlockData: .init(masterPassword: "test"))
            Issue.record("Expected lazy open to reject a 3.1 file")
        } catch let error as KDBXReader.Error {
            if case let .unsupportedFormatVersion(major, minor) = error {
                #expect(major == 3)
                #expect(minor == 1)
            } else {
                Issue.record("Wrong KDBXReader.Error: \(error)")
            }
        }
    }

    @Test("parseHeader on a non-KDBX file throws .invalidFileSignature")
    func invalidSignatureSurfacesStructuredError() throws {
        let bogus = Data("not a kdbx file at all".utf8) + Data(repeating: 0, count: 200)

        #expect(throws: KDBXReader.Error.invalidFileSignature) {
            _ = try KDBXReader.parseHeader(bogus)
        }
    }
}
