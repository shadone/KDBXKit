//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct KDBXTests {
    @Test
    func KDBXReaderSimple_Argon2d_AES256() async throws {
        // KDF: argon2d
        // Main Content encryption: AES256CBC
        // Inner Header encryption: ChaCha20
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-argon2d-aes256", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-argon2d-aes256", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "123"), retainsXMLForDiagnostics: true)

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_1)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "57c789c9a7df70a5bb7d10bdae09180a40e35556b8a8064196779219628ddfd4")
        #expect(content.header.encryptionNonce.hexString == "0656009f25f6458a750e210217cd7fc2")

        #expect(content.header.kdfParameters.argon2d != nil)
        #expect(content.header.kdfParameters.argon2d?.params.version == .v1_3)
        #expect(content.header.kdfParameters.argon2d?.params.iterations == 10)
        #expect(content.header.kdfParameters.argon2d?.params.memory == 67_108_864)
        #expect(content.header.kdfParameters.argon2d?.params.parallelism == 12)
        #expect(content.header.kdfParameters.argon2d?.params.salt.hexString == "ddf3bb53e421cf7e2be15ac8556c8228cbb7e0fc60359b61295c6533de645bb7")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.toData().hexString == "89b089183e2dc2c220df1e94feef6d658dacf87dbb4e2a1337e5380f25eed8dc72492e6fb9794329d7fc80b0932ad37a4fca03ae7ea2c17b7e829e5256054496")
        #expect(content.innerHeader.binaryContent.isEmpty == true)

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func KDBXReaderSimple_Argon2id_AES256() async throws {
        // KDF: argon2id
        // Main Content encryption: AES256CBC
        // Inner Header encryption: ChaCha20
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "123"), retainsXMLForDiagnostics: true)

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_0)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "da94766b3643613a3eb6f2a6eab125f2b8f5f4bdcf0dc02bd0e94e9fff8aea38")
        #expect(content.header.encryptionNonce.hexString == "138ccf115923dd1e32d9e70cbc8832b3")

        #expect(content.header.kdfParameters.argon2id != nil)
        #expect(content.header.kdfParameters.argon2id?.params.version == .v1_3)
        #expect(content.header.kdfParameters.argon2id?.params.iterations == 10)
        #expect(content.header.kdfParameters.argon2id?.params.memory == 67_108_864)
        #expect(content.header.kdfParameters.argon2id?.params.parallelism == 12)
        #expect(content.header.kdfParameters.argon2id?.params.salt.hexString == "144c6206ad60ea2bb3fe92522a8553b706e285964440f30b7dbf1d27405c81ef")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.toData().hexString == "f17626dfb97ba00416955501fb794e34f95da47472985d4916accb3e0853c6b6e1c11a42ab6b3265279bd169c16c4a546968deb54760c0a42bc549120f88b55e")
        #expect(content.innerHeader.binaryContent.isEmpty == true)

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func KDBXReaderSimple_AES256_AES256() async throws {
        // KDF: AES256
        // Main Content encryption: AES256CBC
        // Inner Header encryption: ChaCha20
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "123"), retainsXMLForDiagnostics: true)

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_0)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "68809cfbd28cb5e5a6292bc47a0f9da676004855179dde445b6f74c4c90e659b")
        #expect(content.header.encryptionNonce.hexString == "371d051e5d4a9acc290498700c6d22a8")

        #expect(content.header.kdfParameters.aes != nil)
        #expect(content.header.kdfParameters.aes?.params.rounds == 1000)
        #expect(content.header.kdfParameters.aes?.params.salt.hexString == "bff164e9044a359f4b473f882d83fe1e85f4e88ac6caf2c28f0c75e24c8e7569")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.toData().hexString == "40b2e668db617d0cd1ed710ec717e4df17ee5f0f3d5abfd06a41b5e8ff4e061308007e8d04a00df48b28184cb141e5564e5b81266a83c4d019cb4a18cfa141d5")
        #expect(content.innerHeader.binaryContent.isEmpty == true)

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func Format400_Argon2d_ChaCha20() async throws {
        // KDF: argon2d
        // Content encryption: ChaCha20
        // Inner Header encryption: ChaCha20
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/Format400", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/Format400", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "t"), retainsXMLForDiagnostics: true)

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_0)
        #expect(content.header.encryptionAlgorithm == .ChaCha20)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "3bfa79c0795325db317f99f475b559f195d73368da522c12a061a0c2b9efcb13")
        #expect(content.header.encryptionNonce.hexString == "333f87509b6f72908d689430")

        #expect(content.header.kdfParameters.argon2d != nil)
        #expect(content.header.kdfParameters.argon2d?.params.version == .v1_3)
        #expect(content.header.kdfParameters.argon2d?.params.iterations == 2)
        #expect(content.header.kdfParameters.argon2d?.params.memory == 1_048_576)
        #expect(content.header.kdfParameters.argon2d?.params.parallelism == 2)
        #expect(content.header.kdfParameters.argon2d?.params.salt.hexString == "56ac066d2d862ab0c50c00f6143a349df441f2e6910b297da88f50c3c302d9a5")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.toData().hexString == "82e360f53b72fa95c82b32d5129ebe891dd1974f56aeca7221f3ce6ab7b92f4644d0a832501b6eeb05fa2d1bc5a57a532ac3d4954370da171bf558a041ed8c3e")
        #expect(content.innerHeader.binaryContent.isEmpty == false)
        #expect(content.innerHeader.binaryContent[0].shouldBeProtected == false)
        #expect(content.innerHeader.binaryContent[0].data == Data(hexString: "466f726d61743430300a"))

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func Simple_AES256_AES256_readThenWriteThenReadAgain() async throws {
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let referenceKDBXData = try Data(contentsOf: URL(filePath: kdbxFilepath))

        let unlockData = UnlockData(masterPassword: "123")
        var reader = KDBXReader(referenceKDBXData)
        let reference = try reader.parse(unlockData: unlockData)

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        // Exact-equality round-trip — pin salts so the written file is
        // byte-identical to the reference. Production writes auto-regenerate
        // salts (see KDBXWriter.write's `regenerateSalts:` parameter).
        try KDBXWriter(to: outputStream).write(reference, unlockData: unlockData, regenerateSalts: false)
        let writtenKDBXData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var reader2 = KDBXReader(writtenKDBXData)
        let readAgain = try reader2.parse(unlockData: unlockData)

        #expect(readAgain == reference)
    }

    @Test(
        "Real-world KDBX fixtures parse without dropping unknown elements",
        arguments: [
            (file: "Resources/simple-aes256-aes256", password: "123"),
            (file: "Resources/simple-argon2d-aes256", password: "123"),
            (file: "Resources/simple-argon2id-aes256", password: "123"),
            (file: "Resources/Format400", password: "t"),
            // KeePassXC 2.7.10-written fixture with groups, nested groups,
            // unicode/emoji in fields, edit history, and a binary attachment
            // — built via keepassxc-cli on top of simple-argon2id-aes256.
            (file: "Resources/kpxc-rich", password: "123"),
            // KeePassXC 2.7.10 KDBX 4.1 fixture with extras the CLI alone
            // can't produce — TOTP `otp` field, custom string keys
            // (API_TOKEN, Backup Codes, KPH:*), comma-separated tags,
            // ForegroundColor / BackgroundColor, AutoType Association with
            // window matching, entry-level CustomData (KPRPC_JSON), and a
            // group with EnableSearching=False. Built by exporting
            // kpxc-rich to XML, surgically editing it, and re-importing
            // via `keepassxc-cli import`.
            (file: "Resources/kpxc-extras", password: "test"),
            // 30 levels of nested groups, well under our 100-level cap;
            // exercises the recursive parseGroup walk against real
            // (non-synthetic) input.
            (file: "Resources/kpxc-deep-groups", password: "123"),
            // A trashed entry: KeePassXC moved it to an auto-created
            // "Recycle Bin" group (the entry got PreviousParentGroup set
            // to the original root). Built via `keepassxc-cli rm`.
            (file: "Resources/kpxc-recycle", password: "123"),
            // AutoType-with-Associations fixture. Built by writing a
            // minimal hand-crafted XML (with two `<Association>` blocks
            // and a non-trivial DefaultSequence), importing it to KDBX 3.1,
            // and then `keepassxc-cli merge`-ing into a 4.x base — only
            // path to land real Association elements via the CLI.
            (file: "Resources/kpxc-autotype", password: "123"),
            // KeePassXC db-create defaults to KDBX 3.1 — the legacy
            // format read pipeline must produce zero parser warnings on
            // a stock kpxc output, same invariant we hold 4.x fixtures
            // to. Differences exercised: UInt16 header field lengths,
            // hashed (not HMAC) block stream, Salsa20 inner cipher,
            // ISO-8601 dates, inline `<Meta><Binaries>` (empty pool in
            // this fixture; a separate fixture covers populated pools).
            (file: "Resources/kpxc-kdbx31-default", password: "test"),
            // KDBX 3.1 with a populated inline binary pool — same
            // shape kpxc-kdbx31-default exercises plus an entry with
            // two `<Binary Ref>` references and two `<Meta><Binaries>`
            // pool entries (one compressible / one incompressible) so
            // the pool's gunzip and Protected-attribute paths are
            // covered by the regression net.
            (file: "Resources/kpxc-kdbx31-attachments", password: "test"),
        ]
    )
    func fixturesProduceNoParserWarnings(fixture: (file: String, password: String)) async throws {
        // Regression net for silent data loss on round-trips: every element /
        // attribute that the XML reader drops gets accumulated into
        // `KDBXContent.parserWarnings`. The bundled fixtures were written by
        // KeePass / KeePassXC and represent the shape of data we actually
        // encounter; if a future KeePassXC version emits something we don't
        // model, we want a loud test failure here rather than silent loss.
        let path = Bundle.module.path(forResource: fixture.file, ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: fixture.password))
        #expect(
            content.parserWarnings.isEmpty,
            "Unexpected parser warnings on \(fixture.file).kdbx: \(content.parserWarnings)"
        )
    }

    @Test("KeePassXC-rich fixture: structural content survives parse")
    func kpxcRich_structuralExpectations() throws {
        // Generated via keepassxc-cli (KeePassXC 2.7.10) on top of the
        // simple-argon2id-aes256 fixture. Covers groups, nested groups,
        // unicode/emoji in title + notes + username + password, edit history,
        // and a binary attachment routed via the KDBX 4 inner header.
        let path = Bundle.module.path(forResource: "Resources/kpxc-rich", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        let root = content.database.root.group

        // Top-level entries: GitHub + Unicode.
        let topLevelTitles = root.entries.compactMap { entry in
            entry.strings.first(where: { $0.key == "Title" })?.value.bytes.withRevealedString { $0 }
        }
        #expect(topLevelTitles.contains("GitHub"))
        #expect(topLevelTitles.contains("Unicode 测试 🌍"))

        // Nested group: Work → Servers → Prod entry.
        let work = root.groups.first { $0.name == "Work" }
        let servers = work?.groups.first { $0.name == "Servers" }
        let prod = servers?.entries.first
        let prodTitle = prod?.strings.first(where: { $0.key == "Title" })?.value.bytes.withRevealedString { $0 }
        #expect(prodTitle == "Prod")

        // GitHub: two edits ⇒ at least two history records, plus an attachment.
        let github = root.entries.first { entry in
            entry.strings.first(where: { $0.key == "Title" })?.value.bytes.withRevealedString { $0 } == "GitHub"
        }
        #expect((github?.history.count ?? 0) >= 2)
        #expect(github?.binaries.contains { $0.key == "notes.txt" } == true)

        // Unicode survives: title, username, notes.
        let unicode = root.entries.first { entry in
            entry.strings.first(where: { $0.key == "Title" })?.value.bytes.withRevealedString { $0 } == "Unicode 测试 🌍"
        }
        let unicodeUserName = unicode?.strings.first(where: { $0.key == "UserName" })?.value.bytes.withRevealedString { $0 }
        let unicodeNotes = unicode?.strings.first(where: { $0.key == "Notes" })?.value.bytes.withRevealedString { $0 }
        #expect(unicodeUserName == "用户")
        #expect(unicodeNotes == "汉字 + 🌸 + ñ")

        // No silent drops.
        #expect(content.parserWarnings.isEmpty)
    }

    @Test("KeePassXC-extras fixture: custom fields + tags + autotype survive")
    func kpxcExtras_structuralExpectations() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-extras", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))
        let root = content.database.root.group

        let github = findEntry(in: root, titled: "GitHub")
        #expect(github != nil)

        // Custom string fields preserved.
        let keys = Set(github?.strings.map(\.key) ?? [])
        #expect(keys.contains("API_TOKEN"))
        #expect(keys.contains("Backup Codes"))
        #expect(keys.contains("KPH: example.com"))
        #expect(keys.contains("otp"))

        // TOTP URI survives intact through the protected-string round-trip.
        let otp = github?.strings.first(where: { $0.key == "otp" })?.value.bytes.withRevealedString { $0 }
        #expect(otp?.hasPrefix("otpauth://totp/") == true)
        #expect(otp?.contains("secret=JBSWY3DPEHPK3PXP") == true)

        // KeePassXC writes comma-separated tags; our reader splits on
        // either `;` or `,` (KeePassXC normalizes + sorts).
        #expect(github?.tags == ["2fa", "login", "work"])

        // Custom entry colors.
        #expect(github?.foregroundColor == .color(red: 0xFF, green: 0x00, blue: 0x00))
        #expect(github?.backgroundColor == .color(red: 0xFF, green: 0xFF, blue: 0xCC))

        // Entry-level CustomData (e.g. KPRPC plugin data).
        let cd = github?.customData ?? []
        #expect(cd.contains { $0.key == "KPRPC_JSON" })

        // Group-level Tags survive.
        let work = root.groups.first { $0.name == "Work" }
        #expect(work?.tags == ["infrastructure"])

        #expect(content.parserWarnings.isEmpty)
    }

    @Test("AutoType fixture: Associations with window + keystroke survive")
    func kpxcAutoType_structuralExpectations() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-autotype", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))

        let entry = findEntry(in: content.database.root.group, titled: "WithAutoType")
        let autoType = entry?.autoType
        #expect(autoType?.enabled == true)
        #expect(autoType?.defaultSequence == "{USERNAME}{TAB}{PASSWORD}{ENTER}")

        let assoc = autoType?.association ?? []
        #expect(assoc.count == 2)

        let github = assoc.first { $0.window == "GitHub*" }
        #expect(github != nil)
        // Empty KeystrokeSequence: covered by the parser's empty-content
        // tolerance fix earlier in this session.
        #expect(github?.keystrokeSequence == "")

        let gitlab = assoc.first { $0.window == "*GitLab*" }
        #expect(gitlab?.keystrokeSequence == "{USERNAME}{TAB}{TAB}{PASSWORD}")

        #expect(content.parserWarnings.isEmpty)
    }

    @Test("Recycle-bin fixture: trashed entry lives in the Recycle Bin group with PreviousParentGroup set")
    func kpxcRecycle_structuralExpectations() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-recycle", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        let root = content.database.root.group

        // RecycleBinEnabled + RecycleBinUUID pointing at a real (non-zero) group.
        #expect(content.database.meta.recycleBinEnabled == true)
        let binID = content.database.meta.recycleBinUUID
        #expect(binID != nil)
        #expect(binID?.isZero == false)

        // The pointed-at group exists and is named "Recycle Bin".
        let bin = root.groups.first { $0.uuid == binID }
        #expect(bin?.name == "Recycle Bin")

        // The trashed entry lives inside, with PreviousParentGroup
        // pointing at the original root.
        let trashed = bin?.entries.first { entry in
            entry.strings.first(where: { $0.key == "Title" })?.value.bytes.withRevealedString { $0 } == "ToBeTrashed"
        }
        #expect(trashed != nil)
        #expect(trashed?.previousParentGroup == root.uuid)
        #expect(content.parserWarnings.isEmpty)
    }

    private func findEntry(in group: KDBX.Group, titled title: String) -> KDBX.Entry? {
        for entry in group.entries {
            let t = entry.strings.first { $0.key == "Title" }?.value.bytes.withRevealedString { $0 }
            if t == title { return entry }
        }
        for sub in group.groups {
            if let found = findEntry(in: sub, titled: title) { return found }
        }
        return nil
    }

    @Test("KeePassXC-extras fixture: read → write → read round-trip is stable")
    func kpxcExtras_roundTrip() throws {
        // Round-tripping kpxc-extras additionally exercises an
        // edge case the rich fixture doesn't: a 0-byte inner-header
        // binary entry (KeePassXC's import dropped the attachment
        // contents but kept the placeholder). Our writer must
        // preserve the empty placeholder so binary `Ref` indices on
        // the consuming side stay valid.
        let path = Bundle.module.path(forResource: "Resources/kpxc-extras", ofType: "kdbx")!
        let referenceData = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "test")

        var firstReader = KDBXReader(referenceData)
        let firstParse = try firstReader.parse(unlockData: unlock)

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try KDBXWriter(to: outputStream).write(firstParse, unlockData: unlock, regenerateSalts: false)
        let writtenData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var secondReader = KDBXReader(writtenData)
        let secondParse = try secondReader.parse(unlockData: unlock)

        #expect(secondParse == firstParse)
    }

    @Test("KeePassXC-rich fixture: read → write → read round-trip is stable")
    func kpxcRich_roundTrip() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-rich", ofType: "kdbx")!
        let referenceData = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "123")

        var firstReader = KDBXReader(referenceData)
        let firstParse = try firstReader.parse(unlockData: unlock)

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        // Pin salts so the header stays byte-identical; we're testing data
        // preservation through write+read, not salt regeneration.
        try KDBXWriter(to: outputStream).write(firstParse, unlockData: unlock, regenerateSalts: false)
        let writtenData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var secondReader = KDBXReader(writtenData)
        let secondParse = try secondReader.parse(unlockData: unlock)

        // Equality covers Meta + Root + Entries (with protected values
        // compared via decryption), so this catches any field we silently
        // drop or mangle through the writer.
        #expect(secondParse == firstParse)
    }

    @Test
    func Format400_Argon2d_ChaCha20_readThenWriteThenReadAgain() async throws {
        // KDF: argon2d
        // Main Content encryption: ChaCha20
        // Inner Header encryption: ChaCha20
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/Format400", ofType: "kdbx")!
        let referenceKDBXData = try Data(contentsOf: URL(filePath: kdbxFilepath))

        let unlockData = UnlockData(masterPassword: "t")
        var reader = KDBXReader(referenceKDBXData)
        let reference = try reader.parse(unlockData: unlockData)

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        // Exact-equality round-trip — pin salts so the written file is
        // byte-identical to the reference. Production writes auto-regenerate
        // salts (see KDBXWriter.write's `regenerateSalts:` parameter).
        try KDBXWriter(to: outputStream).write(reference, unlockData: unlockData, regenerateSalts: false)
        let writtenKDBXData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var reader2 = KDBXReader(writtenKDBXData)
        let readAgain = try reader2.parse(unlockData: unlockData)

        #expect(readAgain == reference)
    }
}
