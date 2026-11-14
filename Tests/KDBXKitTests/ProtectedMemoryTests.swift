// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
// SPDX-License-Identifier: BSD-2-Clause
import Foundation
import Testing
@testable import KDBXKit

@Suite("Protected resident values")
struct ProtectedMemoryTests {
    @Test("Independent protections retain ciphertext and reveal only scoped bytes")
    func ciphertext() {
        let input = Data("a protected attachment and password".utf8)
        let first = ProtectedBytes(input)
        let second = ProtectedBytes(input)
        #expect(first.ciphertext != input)
        #expect(first.ciphertext != second.ciphertext)
        #expect(first == second)
        #expect(first.count == input.count)
        #expect(first.withRevealedBytes { Data($0) } == input)
    }

    @Test("Empty values and deprecated constructors still honor protection")
    func compatibility() {
        let empty = ProtectedBytes(Data())
        #expect(empty.isEmpty)
        #expect(empty.withRevealedBytes { $0.isEmpty })
        let secret = SecureBytes(utf8: "compatibility")
        guard case .innerProtected = KDBX.ProtectedString.Value.unprotected(secret) else {
            Issue.record("Legacy constructor bypassed protection")
            return
        }
        guard case .memoryProtected = KDBX.ProtectedString.Value.protectedInMemory(secret) else {
            Issue.record("Legacy memory hint bypassed protection")
            return
        }
        guard case .protectedInline = KDBX.ProtectedBinary.Value.inline(Data([1]), protected: true) else {
            Issue.record("Legacy binary constructor bypassed protection")
            return
        }
    }

    @Test("XML memory hints retain encrypted storage and their wire attribute")
    func memoryHintRoundTrip() throws {
        var content = KDBXContent.makeEmpty(databaseName: "Memory", kdf: .aes(.init(salt: Data(repeating: 7, count: 32), rounds: 1), additional: [:]))
        var entry = KDBX.Entry(uuid: UUID())
        entry.strings = [.init(key: "hint", value: .memoryProtected("xml-only-hint")), .init(key: "Password", value: .innerProtected("inner-secret-canary"))]
        content.database.root.group.entries.append(entry)
        let unlock = UnlockData(masterPassword: "pw")
        let stream = OutputStream(toMemory: ())
        stream.open()
        defer { stream.close() }
        try KDBXWriter(to: stream).write(content, unlockData: unlock)
        var reader = KDBXReader(try #require(stream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data))
        let reopened = try reader.parse(unlockData: unlock, retainsXMLForDiagnostics: true)
        let hint = try #require(reopened.database.root.group.entries.first?.strings.first(where: { $0.key == "hint" }))
        guard case .memoryProtected = hint.value else { Issue.record("Memory hint lost encrypted storage")
            return
        }
        #expect(hint.value.revealedString == "xml-only-hint")
        #expect(!reopened.parserWarnings.contains(where: { $0.contains("Protect in memory not yet implemented") }))
        let xml = try #require(reader.xmlDocument)
        #expect(xml.contains("ProtectInMemory=\"True\""))
        #expect(!xml.contains("inner-secret-canary"))
    }

    @Test("Binary protection follows flag changes and assignments without losing bytes")
    func binaryFlags() {
        let bytes = Data([0, 1, 2, 255])
        var binary = InnerHeader.BinaryContent(shouldBeProtected: true, data: bytes)
        #expect(binary.isStoredEncrypted)
        #expect(binary.withRevealedBytes { Data($0) } == bytes)
        binary.data = Data([3])
        #expect(binary.isStoredEncrypted)
        #expect(binary.data == Data([3]))
        binary.shouldBeProtected = false
        #expect(!binary.isStoredEncrypted)
        binary.shouldBeProtected = true
        #expect(binary.isStoredEncrypted)
        #expect(binary.data == Data([3]))
    }

    @Test("Secret factories and compatibility String factory retain encrypted storage")
    func strings() {
        let value = KDBX.ProtectedString.Value.innerProtected("secret")
        guard case .innerProtected = value else { Issue.record("Expected encrypted resident storage")
            return
        }
        #expect(value.withRevealedString { $0 } == "secret")
        #expect(KDBX.ProtectedString.Value.unprotected("secret") == value)
        let memory = KDBX.ProtectedString.Value.memoryProtected("hint")
        #expect(memory.withRevealedString { $0 } == "hint")
    }

    @Test("Canonical inline factory and binary sources honor memory protection")
    func inline() throws {
        let bytes = Data([1, 2, 3])
        let inline = KDBX.ProtectedBinary.Value.makeInline(bytes, protected: true)
        guard case .protectedInline = inline else { Issue.record("Expected protected inline storage")
            return
        }
        #expect(inline.inlineData == bytes)
        #expect(inline.isProtected)
        let source = DataBinarySource(bytes, shouldBeProtected: true)
        #expect(source.isStoredEncrypted)
        var sink = DataSink()
        try source.stream(into: &sink)
        #expect(sink.data == bytes)
    }
}
