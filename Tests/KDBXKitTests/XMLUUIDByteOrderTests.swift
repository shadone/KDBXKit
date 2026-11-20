//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// XML `<UUID>` values are the UUID's 16 bytes in RFC 4122 order, base64
/// encoded (KeePass's `PwUuid`, KeePassXC's `QUuid::toRfc4122`). Reading
/// them reversed round-trips files unchanged but gives every entry and
/// group a UUID other clients don't know, which breaks anything that
/// carries a UUID as text, such as field references (`{REF:P@I:<uuid>}`).
@Suite("XML UUIDs use RFC 4122 byte order")
struct XMLUUIDByteOrderTests {
    /// `00010203-0405-0607-0809-0a0b0c0d0e0f` is written as these bytes.
    static let sequential = UUID(uuidString: "00010203-0405-0607-0809-0A0B0C0D0E0F")!
    static let sequentialBase64 = "AAECAwQFBgcICQoLDA0ODw=="

    @Test("Entry UUIDs in a KeePassXC file match the ones KeePassXC shows")
    func keePassXCFixture_uuidsMatchKeePassXC() throws {
        let path = try #require(Bundle.module.path(forResource: "Resources/kpxc-rich", ofType: "kdbx"))
        let data = try Data(contentsOf: URL(filePath: path))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        let github = content.database.root.group.entries.first { entry in
            entry.strings.first(where: { $0.key == "Title" })?.value.bytes.withRevealedString { $0 } == "GitHub"
        }
        // `keepassxc-cli show kpxc-rich.kdbx GitHub` prints
        // "Uuid: {40d15baa-cbef-4d33-a4c1-4cc5646d8efb}".
        #expect(github?.uuid == UUID(uuidString: "40D15BAA-CBEF-4D33-A4C1-4CC5646D8EFB"))
    }

    @Test("The writer emits the bytes in order and the reader takes them back")
    func writerAndReader_useRFC4122Order() throws {
        var content = KDBXContent.makeEmpty(databaseName: "UUIDs")
        var entry = KDBX.Entry(uuid: Self.sequential)
        entry.strings = [.init(key: "Title", value: .regular("Sequential"))]
        content.database.root.group.entries = [entry]
        let unlock = UnlockData(masterPassword: "uuid")

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        let data = try #require(outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data)

        var reader = KDBXReader(data)
        let decoded = try reader.parse(unlockData: unlock, retainsXMLForDiagnostics: true)
        let xml = try #require(reader.xmlDocument)
        #expect(xml.contains("<UUID>\(Self.sequentialBase64)</UUID>"))
        #expect(decoded.database.root.group.entries.first?.uuid == Self.sequential)
    }
}
