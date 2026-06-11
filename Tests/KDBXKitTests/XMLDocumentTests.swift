//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct MockCryptor: Encryptable, Decryptable {
    func encrypt(_ input: any DataProtocol) -> any DataProtocol {
        input
    }

    func decrypt(_ input: any DataProtocol) -> any DataProtocol {
        input
    }
}

// A random date for convenience.
// XML document stores dates as number of full seconds since .NET epoch, so the dates we read
// should not have any sub-second precision so that date comparison in unit tests succeeds.
private let mockDate = Date(secondsSinceDotNetEpoch: 63_884_389_441)

let reference = KDBX(
    meta: .init(
        generator: "KDBXKit",
        // No headerHash: the writer emits only KDBX 4, which omits this
        // KDBX-3-only field, so it does not survive a round trip.
        settingsChanged: mockDate,
        databaseName: "Test Database",
        databaseNameChanged: mockDate,
        databaseDescription: "test database description",
        databaseDescriptionChanged: mockDate,
        defaultUserName: "hello",
        defaultUserNameChanged: mockDate,
        maintenanceHistoryDays: 123,
        color: .color(red: 12, green: 23, blue: 45),
        masterKeyChanged: mockDate,
        masterKeyChangeRec: .never,
        masterKeyChangeForce: .value(42),
        masterKeyChangeForceOnce: false,
        memoryProtection: .init(
            protectTitle: false,
            protectUserName: true,
            protectPassword: false,
            protectURL: true,
            protectNotes: false,
        ),
        customIcons: [
            .init(
                uuid: UUID(),
                data: Data([1, 2, 3]),
                name: "Test Icon",
                lastModificationTime: mockDate,
            ),
        ],
        recycleBinEnabled: true,
        recycleBinUUID: UUID(),
        recycleBinChanged: mockDate,
        entryTemplatesGroup: UUID(),
        entryTemplatesGroupChanged: mockDate,
        historyMaxSize: .value(123),
        lastSelectedGroup: UUID(),
        lastTopVisibleGroup: UUID(),
        customData: [
            .init(key: "Foo", value: "Bar"),
            .init(key: "Hello", value: "World", lastModificationTime: mockDate),
        ],
    ),
    root: .init(
        group: .init(
            uuid: UUID(),
            name: "Root Group",
            notes: "here goes notes",
            iconID: 123,
            customIconUUID: UUID(),
            times: .init(
                creationTime: mockDate,
                lastModificationTime: mockDate,
                lastAccessTime: mockDate,
                expiryTime: mockDate,
                expires: false,
                usageCount: 123_456,
                locationChanged: mockDate,
            ),
            isExpanded: true,
            defaultAutoTypeSequence: "foo",
            enableAutoType: .value(true),
            enableSearching: .null,
            lastTopVisibleEntry: UUID(),
            previousParentGroup: UUID(),
            tags: ["one", "two"],
            customData: [
                .init(key: "Hello", value: "World"),
            ],
            entries: [
                .init(
                    uuid: UUID(),
                    iconID: 42,
                    customIconUUID: UUID(),
                    foregroundColor: .color(red: 1, green: 2, blue: 3),
                    backgroundColor: .default,
                    overrideURL: "https://example.com",
                    qualityCheck: nil,
                    tags: ["a", "b"],
                    previousParentGroup: UUID(),
                    times: .init(
                        creationTime: mockDate,
                        lastModificationTime: mockDate,
                        lastAccessTime: mockDate,
                        expiryTime: mockDate,
                        expires: false,
                        usageCount: 123_456,
                        locationChanged: mockDate,
                    ),
                    strings: [
                        .init(key: "Title", value: .regular("Hello World")),
                        .init(key: "Password", value: .unprotected("god")),
                    ],
                    binaries: [
                        .init(key: "RefBinary", value: .ref(0)),
                        .init(key: "InlineBinary", value: .inline(Data([1, 2, 3]), protected: false)),
                    ],
                    autoType: .init(
                        enabled: true,
                        dataTransferObfuscation: .twoChannelObfuscation,
                        defaultSequence: "blah",
                        association: [
                            .init(window: "a-window", keystrokeSequence: "alt+f4"),
                        ],
                    ),
                    customData: [
                        .init(key: "Foo", value: "Bar"),
                    ],
                    history: [
                        .init(
                            uuid: UUID(),
                            iconID: 42,
                            customIconUUID: UUID(),
                            foregroundColor: .color(red: 1, green: 2, blue: 3),
                            backgroundColor: .default,
                            overrideURL: "https://example.com",
                            qualityCheck: nil,
                            tags: ["a", "b"],
                            previousParentGroup: UUID(),
                            times: .init(
                                creationTime: mockDate,
                                lastModificationTime: mockDate,
                                lastAccessTime: mockDate,
                                expiryTime: mockDate,
                                expires: false,
                                usageCount: 123_456,
                                locationChanged: mockDate,
                            ),
                            strings: [
                                .init(key: "Title", value: .regular("Hello World")),
                                .init(key: "Password", value: .unprotected("god")),
                            ],
                            binaries: [],
                            autoType: .init(
                                enabled: true,
                                dataTransferObfuscation: .twoChannelObfuscation,
                                defaultSequence: "blah",
                                association: [
                                    .init(window: "a-window", keystrokeSequence: "alt+f4"),
                                ],
                            ),
                            customData: [
                                .init(key: "Foo", value: "Bar"),
                            ],
                        ),
                    ],
                ),
            ],
            groups: [
            ],
        ),
        deletedObjects: [],
    )
)

struct XMLDocumentTests {
    @Test
    func XMLDocumentReader_empty() async throws {
        let xmlFilepath = Bundle.module.path(forResource: "Resources/database-encrypted-empty", ofType: "xml")!
        let xmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)

        // The fixture has no protected strings, so the keystream source's
        // key/nonce never actually run — a benign InnerHeader is enough.
        let reader = try XMLDocumentReader(xmlDocument: xmlDocument, keystreamSource: Self.mockKeystream())
        let database = try reader.parse()

        #expect(database.meta.generator == "KeePassXC")
        #expect(database.meta.databaseName == "test3")
        #expect(database.meta.databaseNameChanged == Date(timeIntervalSince1970: 1_747_996_682))
        #expect(database.meta.maintenanceHistoryDays == 365)
    }

    @Test("Nested Entry/History recursion is depth-capped like group nesting")
    func entryHistoryNestingCapped() throws {
        // parseGroup carries an explicit depth cap to bound stack usage on
        // crafted input; the equally-recursive Entry → History → Entry path
        // needs the same treatment — ~500 parseEntry frames can blow a
        // 512 KiB secondary-thread stack, which is an uncatchable SIGSEGV.
        // History is flat in any real vault, so a small cap is generous.
        var inner = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID></Entry>"
        for _ in 0..<50 {
            inner = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><History>\(inner)</History></Entry>"
        }
        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <KeePassFile><Meta/><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\(inner)</Group></Root></KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try reader.parse()
        }
    }

    @Test("Malformed XML input throws a typed error, not a crash")
    func malformedXMLThrowsTypedError() {
        // Reaches the XML layer only when decryption succeeds but the
        // payload is garbage — formerly fatal because the init used `try!`.
        let garbage = "<KeePassFile><Meta><Generator>oops"
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try XMLDocumentReader(xmlDocument: garbage, keystreamSource: Self.mockKeystream())
        }
    }

    @Test("Non-UTF-8-shaped string still rejected without crashing")
    func nonXMLInputThrowsTypedError() {
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try XMLDocumentReader(xmlDocument: "", keystreamSource: Self.mockKeystream())
        }
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try XMLDocumentReader(xmlDocument: "not xml at all", keystreamSource: Self.mockKeystream())
        }
    }

    // Note: a "write then read with MockCryptor (identity)" test used
    // to live here. After C-7's lazy refactor, the reader always
    // routes Protected="True" values through a real KeystreamSource,
    // and there's no useful identity stub — `writeThenReadWithInnerEncryption`
    // below exercises the same round-trip path with real ChaCha20.

    @Test
    func writeThenReadWithInnerEncryption() throws {
        let innerHeader = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: Data(hexString: "584f97811553076c32b4ca004c19b77421280b5e596dd0f735c8d30e3063556c76b8cc3e63aed982e6fba693c6bbf21371db2c5e0d569e61e0655f59694093d8")!,
            binaryContent: []
        )

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        let writer = XMLDocumentWriter(
            to: outputStream,
            encryptor: try innerHeader.makeEncryptor()
        )
        try writer.write(reference)

        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let xmlDocument = String(validating: data, as: UTF8.self)!

        let reader = try XMLDocumentReader(
            xmlDocument: xmlDocument,
            keystreamSource: try innerHeader.makeKeystreamSource()
        )
        let parsed = try reader.parse()

        #expect(parsed == reference)
    }

    // MARK: Inline binary Protected attribute round-trip

    //
    // KDBX 3.1 carries the binary protection flag inline on the
    // entry's `<Value Protected="True">base64</Value>` element. KDBX
    // 4 typically uses pool refs (`<Value Ref="N"/>`), where the flag
    // lives on the inner header. Inline binaries can still appear in
    // KDBX 4 files written by clients that choose not to use the
    // pool; faithful round-trip means the writer emits the attribute
    // and the reader reads it back.

    private func parseInlineBinaryXML(valueElement: String) throws -> KDBX.ProtectedBinary {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        <Entry>
                            <UUID>BBBBBBBBBBBBBBBBBBBBBA==</UUID>
                            <Binary>
                                <Key>secret.bin</Key>
                                \(valueElement)
                            </Binary>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        let parsed = try reader.parse()
        let entry = parsed.root.group.entries.first!
        return entry.binaries.first!
    }

    @Test("Reader parses <Value Protected=\"True\">…</Value> on inline binary")
    func parser_inlineBinary_protectedTrue() throws {
        // Protected="True" means the on-disk bytes are keystream
        // ciphertext (same as protected strings) — build the fixture by
        // XOR-encrypting the plaintext at offset 0 with the same mock
        // keystream the parse helper hands the reader.
        let plain = Data([1, 2, 3])
        let cipher = Self.mockKeystream().decrypt(ciphertext: plain, at: 0).toData()
        let bin = try parseInlineBinaryXML(
            valueElement: #"<Value Protected="True">\#(cipher.base64EncodedString())</Value>"#
        )
        guard case let .inline(data, protected) = bin.value else {
            Issue.record("Expected inline value, got \(bin.value)")
            return
        }
        #expect(data == plain)
        #expect(protected == true)
    }

    @Test("Reader parses <Value>…</Value> with no attribute as protected=false")
    func parser_inlineBinary_noProtectedAttr() throws {
        let bin = try parseInlineBinaryXML(valueElement: "<Value>AQID</Value>")
        guard case let .inline(data, protected) = bin.value else {
            Issue.record("Expected inline value, got \(bin.value)")
            return
        }
        #expect(data == Data([1, 2, 3]))
        #expect(protected == false)
    }

    @Test("Reader parses Protected=\"False\" explicitly")
    func parser_inlineBinary_protectedFalseExplicit() throws {
        let bin = try parseInlineBinaryXML(valueElement: #"<Value Protected="False">AQID</Value>"#)
        guard case let .inline(_, protected) = bin.value else {
            Issue.record("Expected inline value")
            return
        }
        #expect(protected == false)
    }

    @Test("Writer emits Protected=\"True\" when inline binary is protected")
    func writer_inlineBinary_emitsProtectedAttribute() throws {
        // Build a minimal KDBX with one entry carrying a single protected
        // inline binary. Round-trip through writer → string → reader and
        // confirm the protected flag survives plus the XML contains the
        // attribute literally.
        let kdbx = KDBX(
            meta: .init(generator: "test"),
            root: .init(
                group: .init(
                    uuid: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                    name: "Root",
                    entries: [
                        .init(
                            uuid: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
                            binaries: [
                                .init(key: "p.bin", value: .inline(Data([9, 8, 7]), protected: true)),
                                .init(key: "u.bin", value: .inline(Data([1, 2, 3]), protected: false)),
                            ]
                        ),
                    ]
                ),
                deletedObjects: []
            )
        )

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        let innerHeader = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: Data(repeating: 7, count: 64),
            binaryContent: []
        )
        let writer = XMLDocumentWriter(to: outputStream, encryptor: try innerHeader.makeEncryptor())
        try writer.write(kdbx)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let xml = String(validating: data, as: UTF8.self)!

        // The protected attribute is on p.bin's Value (whose content is
        // now keystream ciphertext — NOT the raw CQgH bytes), and absent
        // on u.bin's Value, which stays raw base64.
        #expect(xml.contains(#"<Value Protected="True">"#))
        #expect(!xml.contains(#"<Value Protected="True">CQgH</Value>"#))
        #expect(xml.contains("<Value>AQID</Value>"))

        // Round-trip: re-read and confirm flags AND bytes survived (the
        // reader keystream-decrypts the protected one).
        let reader = try XMLDocumentReader(
            xmlDocument: xml,
            keystreamSource: try innerHeader.makeKeystreamSource()
        )
        let parsed = try reader.parse()
        let bins = parsed.root.group.entries.first!.binaries
        guard case let .inline(d1, p1) = bins[0].value, p1 == true else {
            Issue.record("p.bin lost its protected flag")
            return
        }
        #expect(d1 == Data([9, 8, 7]))
        guard case let .inline(d2, p2) = bins[1].value, p2 == false else {
            Issue.record("u.bin gained a protected flag")
            return
        }
        #expect(d2 == Data([1, 2, 3]))
    }

    // MARK: Lenient parsing of negative integer fields

    //
    // The XSD declares `MaintenanceHistoryDays` and `UsageCount` as
    // `xs:unsignedInt` / `xs:unsignedLong` (no sentinel), and `HistoryMaxItems` /
    // `HistoryMaxSize` / `MasterKeyChangeRec` / `MasterKeyChangeForce` as
    // signed with `-1` meaning "unlimited" / "never". A corrupt producer that
    // emits some other negative value must not crash the reader.

    private func parseMetaXML(_ metaBody: String) throws -> KDBX.Meta {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta>\(metaBody)</Meta>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        return try reader.parse().meta
    }

    private func parseGroupTimesXML(_ timesBody: String) throws -> KDBX.Times? {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        <Times>\(timesBody)</Times>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        return try reader.parse().root.group.times
    }

    @Test
    func parser_negativeMaintenanceHistoryDays_dropsField() throws {
        let meta = try parseMetaXML("<MaintenanceHistoryDays>-5</MaintenanceHistoryDays>")
        #expect(meta.maintenanceHistoryDays == nil)
    }

    @Test
    func parser_garbageMaintenanceHistoryDays_dropsField() throws {
        let meta = try parseMetaXML("<MaintenanceHistoryDays>abc</MaintenanceHistoryDays>")
        #expect(meta.maintenanceHistoryDays == nil)
    }

    @Test
    func parser_positiveMaintenanceHistoryDays_preserved() throws {
        let meta = try parseMetaXML("<MaintenanceHistoryDays>365</MaintenanceHistoryDays>")
        #expect(meta.maintenanceHistoryDays == 365)
    }

    @Test
    func parser_negativeUsageCount_dropsField() throws {
        let times = try parseGroupTimesXML("<UsageCount>-1</UsageCount>")
        #expect(times?.usageCount == nil)
    }

    @Test
    func parser_positiveUsageCount_preserved() throws {
        let times = try parseGroupTimesXML("<UsageCount>42</UsageCount>")
        #expect(times?.usageCount == 42)
    }

    @Test
    func parser_minusOneHistoryMaxItems_unlimited() throws {
        let meta = try parseMetaXML("<HistoryMaxItems>-1</HistoryMaxItems>")
        #expect(meta.historyMaxItems == .unlimited)
    }

    @Test
    func parser_otherNegativeHistoryMaxItems_unlimited() throws {
        let meta = try parseMetaXML("<HistoryMaxItems>-7</HistoryMaxItems>")
        #expect(meta.historyMaxItems == .unlimited)
    }

    @Test
    func parser_otherNegativeHistoryMaxSize_unlimited() throws {
        let meta = try parseMetaXML("<HistoryMaxSize>-99</HistoryMaxSize>")
        #expect(meta.historyMaxSize == .unlimited)
    }

    @Test
    func parser_otherNegativeMasterKeyChangeRec_never() throws {
        let meta = try parseMetaXML("<MasterKeyChangeRec>-42</MasterKeyChangeRec>")
        #expect(meta.masterKeyChangeRec == .never)
    }

    @Test
    func parser_minusOneMasterKeyChangeForce_never() throws {
        let meta = try parseMetaXML("<MasterKeyChangeForce>-1</MasterKeyChangeForce>")
        #expect(meta.masterKeyChangeForce == .never)
    }

    // MARK: XML declaration well-formedness

    @Test("Writer emits a valid XML 1.0 declaration (version=, encoding=, standalone=)")
    func writer_emitsValidXMLDeclaration() throws {
        // KeePassXC's strict XML parser rejects declarations missing the
        // mandatory `version="1.0"` attribute with "No root group". Pin the
        // exact triple so a future writer refactor can't drift back.
        let inner = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: Data(hexString: "584f97811553076c32b4ca004c19b77421280b5e596dd0f735c8d30e3063556c76b8cc3e63aed982e6fba693c6bbf21371db2c5e0d569e61e0655f59694093d8")!,
            binaryContent: []
        )
        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        let writer = XMLDocumentWriter(to: outputStream, encryptor: try inner.makeEncryptor())
        try writer.write(reference)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let xml = String(validating: data, as: UTF8.self)!
        let header = xml.split(separator: "\n").first.map(String.init) ?? ""
        #expect(header.contains("<?xml"))
        #expect(header.contains(#"version="1.0""#))
        #expect(header.contains(#"encoding="UTF-8""#))
        #expect(header.contains(#"standalone="yes""#))
    }

    // MARK: AutoType Association — empty fields tolerated

    private func parseAutoTypeAssociationXML(window: String, keystrokeSequence: String) throws -> KDBX.AutoType.Association? {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        <Entry>
                            <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                            <AutoType>
                                <Association>
                                    \(window)
                                    \(keystrokeSequence)
                                </Association>
                            </AutoType>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        return try reader.parse().root.group.entries.first?.autoType?.association.first
    }

    @Test
    func parser_emptyAssociationFields_parseAsEmptyStrings() throws {
        // KeePass / KeePassXC commonly emit empty `<Window/>` /
        // `<KeystrokeSequence/>` when the user leaves the field blank
        // (meaning "use parent default"). Must not throw.
        let assoc = try parseAutoTypeAssociationXML(
            window: "<Window></Window>",
            keystrokeSequence: "<KeystrokeSequence></KeystrokeSequence>"
        )
        #expect(assoc?.window == "")
        #expect(assoc?.keystrokeSequence == "")
    }

    @Test
    func parser_selfClosingAssociationFields_parseAsEmptyStrings() throws {
        let assoc = try parseAutoTypeAssociationXML(
            window: "<Window/>",
            keystrokeSequence: "<KeystrokeSequence/>"
        )
        #expect(assoc?.window == "")
        #expect(assoc?.keystrokeSequence == "")
    }

    @Test
    func parser_populatedAssociationFields_preserved() throws {
        let assoc = try parseAutoTypeAssociationXML(
            window: "<Window>chrome*</Window>",
            keystrokeSequence: "<KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</KeystrokeSequence>"
        )
        #expect(assoc?.window == "chrome*")
        #expect(assoc?.keystrokeSequence == "{USERNAME}{TAB}{PASSWORD}{ENTER}")
    }

    @Test
    func parser_missingAssociationElement_throws() throws {
        // Element entirely missing is still a corruption — per XSD both
        // sub-elements are required (just allowed to be empty).
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        <Entry>
                            <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                            <AutoType>
                                <Association>
                                    <Window>chrome*</Window>
                                </Association>
                            </AutoType>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try reader.parse()
        }
    }

    // MARK: Group nesting depth cap

    private func buildNestedGroupsXML(depth: Int) -> String {
        var openTags = ""
        var closeTags = ""
        for _ in 0..<depth {
            openTags += "<Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>"
            closeTags = "</Group>" + closeTags
        }
        return """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        \(openTags)\(closeTags)
                    </Group>
                </Root>
            </KeePassFile>
            """
    }

    @Test
    func parser_groupNestingUnderCap_succeeds() throws {
        // Lower the cap so we can exercise the boundary at depths the
        // XML parser handles trivially. Real production cap is 100.
        let xml = buildNestedGroupsXML(depth: 5)
        var reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        reader.maxGroupNestingDepth = 10
        _ = try reader.parse()
    }

    @Test
    func parser_groupNestingOverCap_throws() throws {
        let xml = buildNestedGroupsXML(depth: 15)
        var reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        reader.maxGroupNestingDepth = 10
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try reader.parse()
        }
    }

    // MARK: Parser warnings (unknown elements / attributes)

    @Test
    func parser_unknownElementProducesWarning() throws {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta>
                    <SomeFutureKeePassXCField>hello</SomeFutureKeePassXCField>
                </Meta>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        _ = try reader.parse()
        #expect(reader.collectedWarnings.contains { $0.contains("SomeFutureKeePassXCField") })
    }

    @Test
    func parser_unknownAttributeProducesWarning() throws {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        <Entry>
                            <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                            <String>
                                <Key>Title</Key>
                                <Value SomeUnknownAttr="x">hi</Value>
                            </String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        _ = try reader.parse()
        #expect(reader.collectedWarnings.contains { $0.contains("SomeUnknownAttr") })
    }

    @Test
    func parser_cleanInputProducesNoWarnings() throws {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta>
                    <Generator>KDBXKit</Generator>
                    <DatabaseName>x</DatabaseName>
                </Meta>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        _ = try reader.parse()
        #expect(reader.collectedWarnings.isEmpty)
    }

    // MARK: Tags parsing

    private func parseGroupTagsXML(_ tagsBody: String) throws -> [String] {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta/>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                        <Tags>\(tagsBody)</Tags>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: Self.mockKeystream())
        return try reader.parse().root.group.tags
    }

    @Test
    func parser_trailingSemicolonInTags_droppedNotEmpty() throws {
        #expect(try parseGroupTagsXML("a;") == ["a"])
    }

    @Test
    func parser_consecutiveSemicolonsInTags_collapsed() throws {
        #expect(try parseGroupTagsXML("a;;b") == ["a", "b"])
    }

    @Test
    func parser_onlySemicolonsInTags_yieldsEmpty() throws {
        #expect(try parseGroupTagsXML(";;;") == [])
    }

    @Test
    func parser_normalTags_preserved() throws {
        #expect(try parseGroupTagsXML("one;two;three") == ["one", "two", "three"])
    }

    @Test
    func parser_commaSeparatedTags_split() throws {
        // KeePassXC emits comma-separated tags, not semicolon-separated.
        #expect(try parseGroupTagsXML("2fa,login,work") == ["2fa", "login", "work"])
    }

    @Test
    func parser_mixedSeparatorTags_split() throws {
        // KeePass 2 (.NET) accepts both `;` and `,` on input — be lenient.
        #expect(try parseGroupTagsXML("a;b,c;d") == ["a", "b", "c", "d"])
    }

    /// Builds a no-op-equivalent `KeystreamSource` for fixtures that
    /// either have zero protected strings (so the source is never
    /// invoked) or were written with `MockCryptor` (identity cipher).
    /// In the second case, the test relies on the reader producing
    /// `.lazyInnerCipher` values that round-trip through `==` against
    /// the reference structure — `==` decrypts the lazy values, and
    /// since the writer didn't actually encrypt, the bytes match the
    /// reference plaintext.
    ///
    /// Caveat: this only works because `MockCryptor` is identity. If a
    /// future test mixes a real encrypting writer with this mock
    /// keystream, the reader will hand back gibberish — `==` will
    /// fail loudly, which is the right outcome.
    private static func mockKeystream() -> KeystreamSource {
        KeystreamSource(
            algorithm: .chacha20,
            key: SecureBytes(Data(repeating: 0, count: 32)),
            nonce: Data(repeating: 0, count: 12)
        )
    }
}
