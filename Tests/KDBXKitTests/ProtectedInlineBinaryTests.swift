//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Per the KDBX spec (and KeePass/KeePassXC behavior), every
/// `Protected="True"` value — strings AND inline binaries — is XOR'd with
/// the shared inner keystream, consumed in document order. Treating the
/// flag as inert on binaries is self-consistent within KDBXKit but
/// disagrees with other clients: the attachment imports as ciphertext and
/// every later keystream offset shifts, silently garbling all subsequent
/// passwords.
@Suite("Protected inline binaries ride the inner stream")
struct ProtectedInlineBinaryTests {
    private func makeKeystream() -> KeystreamSource {
        KeystreamSource(
            algorithm: .chacha20,
            key: SecureBytes(Data(repeating: 7, count: 32)),
            nonce: Data(repeating: 3, count: 12)
        )
    }

    @Test("Reader decrypts a protected inline binary and advances the keystream cursor")
    func readerDecryptsAndAdvances() throws {
        let keystream = makeKeystream()
        let binaryPlain = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let passwordPlain = Data("hunter2".utf8)

        // KeePass consumes the keystream in document order: the binary's
        // bytes first, then the password's (XOR encrypt == decrypt).
        let binaryCipher = keystream.decrypt(ciphertext: binaryPlain, at: 0).toData()
        let passwordCipher = keystream.decrypt(ciphertext: passwordPlain, at: binaryPlain.count).toData()

        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <KeePassFile><Meta/><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
            <Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
            <Binary><Key>blob.bin</Key><Value Protected="True">\(binaryCipher.base64EncodedString())</Value></Binary>\
            <String><Key>Password</Key><Value Protected="True">\(passwordCipher.base64EncodedString())</Value></String>\
            </Entry></Group></Root></KeePassFile>
            """
        let reader = try XMLDocumentReader(xmlDocument: xml, keystreamSource: keystream)
        let database = try reader.parse()
        let entry = try #require(database.root.group.entries.first)

        guard case let .inline(data, protected) = try #require(entry.binaries.first).value else {
            Issue.record("Expected an inline binary")
            return
        }
        #expect(data == binaryPlain, "inline protected binary must be keystream-decrypted")
        #expect(protected)

        // The password AFTER the binary in document order only decrypts
        // correctly if the binary consumed its keystream bytes.
        let password = try #require(entry.strings.first(where: { $0.key == "Password" }))
        #expect(password.value.revealedString == "hunter2")
    }

    @Test("Writer encrypts a protected inline binary; full round trip preserves it and later passwords")
    func writerRoundTrip() throws {
        var content = KDBXContent.makeEmpty(
            databaseName: "Inline",
            kdf: .aes(.init(salt: Data(repeating: 7, count: 32), rounds: 1), additional: [:])
        )
        let blob = Data((0..<300).map { UInt8($0 & 0xFF) })
        var entry = KDBX.Entry(uuid: UUID())
        entry.binaries = [.init(key: "blob.bin", value: .inline(blob, protected: true))]
        entry.strings = [
            .init(key: "Title", value: .regular("T")),
            .init(key: "Password", value: .unprotected("after-the-binary")),
        ]
        content.database.root.group.entries.append(entry)

        let unlock = UnlockData(masterPassword: "pw")
        let stream = OutputStream(toMemory: ())
        stream.open()
        defer { stream.close() }
        try KDBXWriter(to: stream).write(content, unlockData: unlock)
        let written = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        let reopened = try KDBXReader.parse(written, unlockData: unlock)
        let reopenedEntry = try #require(reopened.database.root.group.entries.first)
        guard case let .inline(data, protected) = try #require(reopenedEntry.binaries.first).value else {
            Issue.record("Expected an inline binary")
            return
        }
        #expect(data == blob)
        #expect(protected)
        let password = try #require(reopenedEntry.strings.first(where: { $0.key == "Password" }))
        #expect(password.value.revealedString == "after-the-binary")

        // And the on-disk XML must NOT carry the blob as raw base64 —
        // that is what every other client would XOR-corrupt on open.
        var diagnosticReader = KDBXReader(written)
        _ = try diagnosticReader.parse(unlockData: unlock, retainsXMLForDiagnostics: true)
        let xmlText = try #require(diagnosticReader.xmlDocument)
        #expect(!xmlText.contains(blob.base64EncodedString()))
    }
}
