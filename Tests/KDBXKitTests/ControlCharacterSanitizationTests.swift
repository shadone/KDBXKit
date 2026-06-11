//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Characters outside the XML 1.0 §2.2 `Char` production (e.g. `0x01`,
/// `0x0B`) are illegal in a document even as character references. If the
/// serializer emits them raw, the resulting vault is ill-formed XML that
/// no client — including KDBXKit itself — can reopen: one pasted control
/// character in a Notes field would make the next save a total loss.
@Suite("XML control-character sanitization on write")
struct ControlCharacterSanitizationTests {
    private static let cheapKDF = KDFParameters.aes(
        .init(salt: Data(repeating: 7, count: 32), rounds: 1),
        additional: [:]
    )

    @Test("A vault with control characters in unprotected fields reopens after save")
    func controlCharactersRoundTrip() throws {
        var content = KDBXContent.makeEmpty(databaseName: "Ctl", kdf: Self.cheapKDF)
        let entry = KDBX.Entry(uuid: UUID(), strings: [
            .init(key: "Title", value: .regular("Bad\u{01}Title")),
            .init(key: "Notes", value: .regular("line1\nline2\ttab\rcr\u{0B}vt")),
        ])
        content.database.root.group.entries.append(entry)

        let unlock = UnlockData(masterPassword: "pw")
        let stream = OutputStream(toMemory: ())
        stream.open()
        defer { stream.close() }
        try KDBXWriter(to: stream).write(content, unlockData: unlock)
        let data = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // The file must reopen — an ill-formed document here is vault loss.
        let reopened = try KDBXReader.parse(data, unlockData: unlock)
        let strings = reopened.database.root.group.entries[0].strings

        // Illegal scalars are replaced with U+FFFD; the rest of the value
        // survives intact.
        #expect(stringValue(strings, "Title") == "Bad\u{FFFD}Title")

        // Legal whitespace controls (tab, LF, CR) round-trip unchanged;
        // only the illegal vertical tab is replaced.
        #expect(stringValue(strings, "Notes") == "line1\nline2\ttab\rcr\u{FFFD}vt")
    }

    @Test("Sanitization also covers attribute values")
    func controlCharacterInAttributeValue() {
        let root = Node.element(name: "Root")
        root.attributes = [(name: "A", value: "x\u{02}y")]
        let document = Document()
        document.root = root
        let xml = XMLSerializer(indentation: "\t").serialize(document)

        // Re-parsing the serializer's own output must not fail.
        #expect(throws: Never.self) {
            _ = try Document(string: xml)
        }
    }

    private func stringValue(_ strings: [KDBX.ProtectedString], _ key: String) -> String? {
        guard let value = strings.first(where: { $0.key == key })?.value else { return nil }
        return value.withRevealedString { $0 }
    }
}
