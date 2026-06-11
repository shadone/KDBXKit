//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
#if canImport(FoundationXML)
import FoundationXML
#endif
@testable import KDBXKit

/// Always-on proxy for the KeePassXC interop net.
///
/// `KeePassXCInteropTests` is the historically highest-yield suite (it caught
/// the missing `version="1.0"` XML declaration, the tag-separator bug, keyfile
/// non-normalization) — but it is gated on `keepassxc-cli` and silently
/// evaporates on a runner without it. These tests validate the *writer's own
/// XML* with no external binary, so the most important interop bug class —
/// "we emit XML a strict third-party parser rejects" — always has a net.
///
/// They deliberately do not need KeePassXC: they decrypt our own output via
/// `retainsXMLForDiagnostics` and check well-formedness + the XML prolog.
@Suite("Writer XML validity (always-on interop proxy)")
struct WriterXMLValidityTests {
    /// Round-trip `content` through the eager writer and return the decrypted
    /// inner XML document. The eager writer shares `XMLDocumentWriter` with
    /// the streaming path, so validating it covers both serializers' prolog +
    /// element shape.
    private func innerXML(of content: KDBXContent, unlock: UnlockData) throws -> String {
        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var reader = KDBXReader(data)
        _ = try reader.parse(unlockData: unlock, retainsXMLForDiagnostics: true)
        return try #require(reader.xmlDocument, "writer produced no diagnostic XML")
    }

    /// Assert `xml` parses as well-formed XML. Uses Foundation's `XMLParser`,
    /// which is available on Darwin and Linux (FoundationXML) with no external
    /// tool — so this check runs everywhere.
    private func expectWellFormed(_ xml: String, _ label: String) {
        final class Sink: NSObject, XMLParserDelegate {
            nonisolated(unsafe) var error: (any Error)?
            func parser(_ parser: XMLParser, parseErrorOccurred parseError: any Error) {
                error = parseError
            }
        }
        let parser = XMLParser(data: Data(xml.utf8))
        let sink = Sink()
        parser.delegate = sink
        let ok = parser.parse()
        #expect(ok && sink.error == nil, "\(label): malformed XML — \(sink.error.map { "\($0)" } ?? "parse returned false")")
    }

    /// The XML prolog must carry a complete declaration with `version="1.0"`.
    /// This is the exact shape the writer once got wrong (`<?xml encoding=…?>`
    /// with no version), which our lenient reader accepted but KeePassXC
    /// rejected with "No root group".
    private func expectValidProlog(_ xml: String, _ label: String) {
        let head = xml.prefix(60)
        #expect(head.hasPrefix("<?xml "), "\(label): missing XML declaration; prolog was \(head.debugDescription)")
        #expect(head.contains("version=\"1.0\""), "\(label): XML declaration lacks version=\"1.0\"; prolog was \(head.debugDescription)")
    }

    /// Rebuild `base`'s header with a different cipher/compression, using a
    /// cipher-correct nonce length (AES-CBC 16, ChaCha20 12). The writer
    /// regenerates salts on save, but the in-memory header must already be
    /// self-consistent for the read-back.
    private func reheader(
        _ base: Header,
        cipher: Header.EncryptionAlgorithm,
        compression: Header.CompressionAlgorithm
    ) -> Header {
        let nonceLength = cipher == .AES256CBC ? 16 : 12
        return Header(
            formatVersion: base.formatVersion,
            encryptionAlgorithm: cipher,
            compressionAlgorithm: compression,
            masterSalt: base.masterSalt,
            encryptionNonce: Data(repeating: 0, count: nonceLength),
            kdfParameters: base.kdfParameters,
            publicCustomData: base.publicCustomData
        )
    }

    private func sampleContent() -> KDBXContent {
        var content = KDBXContent.makeEmpty(databaseName: "Validity")
        var entry = KDBX.Entry(uuid: UUID())
        entry.strings = [
            .init(key: "Title", value: .regular("Account")),
            .init(key: "UserName", value: .regular("alice")),
            // A protected field exercises the inner-stream cipher + the
            // Protected="True" attribute path in the serializer.
            .init(key: "Password", value: .unprotected(SecureBytes(utf8: "s3cret <&> \"quote\""))),
            // Reserved XML characters in a plaintext field force the escaper.
            .init(key: "Notes", value: .regular("a < b & c > d \"e\" 'f'")),
        ]
        content.database.root.group.entries = [entry]
        return content
    }

    @Test("ChaCha20 + gzip writer output is well-formed with a valid prolog")
    func chacha20Gzip() throws {
        var content = sampleContent()
        content.header = reheader(content.header, cipher: .ChaCha20, compression: .gzip)
        let xml = try innerXML(of: content, unlock: UnlockData(masterPassword: "pw"))
        expectValidProlog(xml, "chacha20+gzip")
        expectWellFormed(xml, "chacha20+gzip")
    }

    @Test("AES-256-CBC, no compression writer output is well-formed with a valid prolog")
    func aesNoCompression() throws {
        var content = sampleContent()
        content.header = reheader(content.header, cipher: .AES256CBC, compression: .none)
        let xml = try innerXML(of: content, unlock: UnlockData(masterPassword: "pw"))
        expectValidProlog(xml, "aes+none")
        expectWellFormed(xml, "aes+none")
    }

    @Test("An empty vault still emits a well-formed document with a valid prolog")
    func emptyVault() throws {
        let content = KDBXContent.makeEmpty(databaseName: "Empty")
        let xml = try innerXML(of: content, unlock: UnlockData(masterPassword: "pw"))
        expectValidProlog(xml, "empty")
        expectWellFormed(xml, "empty")
    }

    @Test("A vault migrated from KDBX 3.1 emits well-formed 4.x XML")
    func migratedFrom3x() throws {
        // The 3.x read path uses the ISO-8601 XML dialect; on save we clamp to
        // 4.x and re-serialize. Validate that re-serialized output, since it
        // crosses the dialect boundary the interop suite normally guards.
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "test")
        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: unlock)
        let xml = try innerXML(of: content, unlock: unlock)
        expectValidProlog(xml, "migrated-3x")
        expectWellFormed(xml, "migrated-3x")
    }
}
