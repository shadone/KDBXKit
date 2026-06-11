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

    @Test("KDBX 3.0 input is rejected with typed unsupportedFormatVersion (3.1 is the only supported 3.x)")
    func kdbx30_rejectedWithTypedError() throws {
        // KDBX 3.0 (KeePass 2.10–2.19) used the ArcFour-variant inner
        // stream cipher as its default. We don't ship a working
        // ArcFour-variant keystream and have no plans to — the format
        // is ~15 years old and effectively unused in the wild. Rejecting
        // it at the version gate gives callers a precise typed error
        // (.unsupportedFormatVersion(3, 0)) instead of an opaque
        // .corruptedHeader("Unsupported inner random stream ID: 1").
        //
        // The fixture is built by surgically flipping the minor-version
        // byte of the 3.1 fixture in memory — the rest of the file is
        // structurally a 3.1 file, but the version field reads 3.0.
        // That's the failure shape we'd see if a user handed us an
        // actual 3.0 file: rejected before any cipher / KDF work.
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))
        // File layout: signature1 (4) + signature2 (4) + version (4 LE,
        // low UInt16 minor + high UInt16 major). Byte 8 is the low byte
        // of `minor` — flip 3.1 → 3.0 in place.
        data[8] = 0x00

        do {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))
            Issue.record("Expected .unsupportedFormatVersion")
        } catch let error as KDBXReader.Error {
            if case let .unsupportedFormatVersion(major, minor) = error {
                #expect(major == 3)
                #expect(minor == 0)
            } else {
                Issue.record("Wrong error: \(error)")
            }
        }
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

    @Test("FormatVersion.supported is exactly the readable set {3.1, 4.0, 4.1}")
    func supportedFormatSetIsTheReadableSet() {
        #expect(Header.FormatVersion.supported == [.v3_1, .v4_0, .v4_1])

        #expect(Header.FormatVersion.v3_1.isSupported)
        #expect(Header.FormatVersion.v4_0.isSupported)
        #expect(Header.FormatVersion.v4_1.isSupported)

        // 3.0 (ArcFour-variant inner stream) and any future major are
        // not readable until a reader exists for them.
        #expect(!Header.FormatVersion(major: 3, minor: 0).isSupported)
        #expect(!Header.FormatVersion(major: 5, minor: 0).isSupported)
    }

    @Test("validateSupportedFormat accepts every header parseHeader can return — including 3.1")
    func validateSupportedFormatAcceptsReadableHeaders() throws {
        // A parsed 4.x header passes.
        let v4Path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let v4Header = try KDBXReader.parseHeader(try Data(contentsOf: URL(filePath: v4Path)))
        #expect(v4Header.formatVersion == .v4_0)
        try KDBXReader.validateSupportedFormat(v4Header) // does not throw

        // A parsed 3.1 header also passes. This is the regression guard:
        // `parseHeader` happily returns a 3.1 header (the read path opens
        // 3.1), so a peek caller running validateSupportedFormat must NOT
        // reject it — the old inline `major == 4` check did, blocking 3.1
        // vaults before the unlock screen.
        let v3Path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let v3Header = try KDBXReader.parseHeader(try Data(contentsOf: URL(filePath: v3Path)))
        #expect(v3Header.formatVersion == .v3_1)
        try KDBXReader.validateSupportedFormat(v3Header) // does not throw
    }
}
