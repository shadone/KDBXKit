//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// A dangling binary ref or a mis-sized binary-source array serializes
/// into a structurally valid, HMAC-clean vault whose attachments are
/// silently gone or bound to the wrong entries. The writers must refuse
/// the save instead — this incident class shipped once (a stale lazy
/// snapshot dropped referenced attachments) and was caught only by a
/// downstream HMAC mismatch.
@Suite("Write-time integrity guard")
struct WriteTimeIntegrityTests {
    private static let cheapKDF = KDFParameters.aes(
        .init(salt: Data(repeating: 7, count: 32), rounds: 1),
        additional: [:]
    )

    private func makeContent(
        binaries: [KDBX.ProtectedBinary],
        history: [KDBX.Entry] = []
    ) -> KDBXContent {
        var content = KDBXContent.makeEmpty(databaseName: "Guard", kdf: Self.cheapKDF)
        var entry = KDBX.Entry(uuid: UUID())
        entry.binaries = binaries
        entry.history = history
        content.database.root.group.entries.append(entry)
        return content
    }

    private func writeToMemory(_ content: KDBXContent) throws {
        let stream = OutputStream(toMemory: ())
        stream.open()
        defer { stream.close() }
        try KDBXWriter(to: stream).write(content, unlockData: UnlockData(masterPassword: "pw"))
    }

    @Test("Eager write refuses a dangling binary ref")
    func eagerWriteRefusesDanglingRef() throws {
        let content = makeContent(binaries: [.init(key: "a.bin", value: .ref(3))])
        #expect(throws: KDBXWriter.Error.self) {
            try writeToMemory(content)
        }
    }

    @Test("Eager write refuses a dangling binary ref inside a history entry")
    func eagerWriteRefusesDanglingRefInHistory() throws {
        var historic = KDBX.Entry(uuid: UUID())
        historic.binaries = [.init(key: "old.bin", value: .ref(0))]
        let content = makeContent(binaries: [], history: [historic])
        #expect(throws: KDBXWriter.Error.self) {
            try writeToMemory(content)
        }
    }

    @Test("Streaming write refuses a dangling binary ref")
    func streamingWriteRefusesDanglingRef() throws {
        let content = makeContent(binaries: [.init(key: "a.bin", value: .ref(0))])
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }
        #expect(throws: KDBXWriter.Error.self) {
            try KDBXWriter.streamingWrite(
                to: outURL,
                content: content,
                binaries: [],
                unlockData: UnlockData(masterPassword: "pw")
            )
        }
        #expect(!FileManager.default.fileExists(atPath: outURL.path))
    }

    @Test("Streaming write refuses a binaries array that doesn't match the pool")
    func streamingWriteRefusesSourceCountMismatch() throws {
        var content = makeContent(binaries: [])
        content.innerHeader.binaryContent = [.init(shouldBeProtected: false, data: Data(count: 4))]
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }
        #expect(throws: KDBXWriter.Error.self) {
            try KDBXWriter.streamingWrite(
                to: outURL,
                content: content,
                binaries: [],
                unlockData: UnlockData(masterPassword: "pw")
            )
        }
        #expect(!FileManager.default.fileExists(atPath: outURL.path))
    }

    /// An `.unknown` KDF must surface as the typed `unsupportedKDF` error
    /// before any serialization — `toVariantDictionary()` has a
    /// `fatalError` for it, and `parseHeader` (credential-free) happily
    /// hands callers headers carrying unknown KDF UUIDs.
    private func withUnknownKDF(_ content: KDBXContent) -> KDBXContent {
        let header = content.header
        return KDBXContent(
            database: content.database,
            header: Header(
                formatVersion: header.formatVersion,
                encryptionAlgorithm: header.encryptionAlgorithm,
                compressionAlgorithm: header.compressionAlgorithm,
                masterSalt: header.masterSalt,
                encryptionNonce: header.encryptionNonce,
                kdfParameters: .unknown(uuid: UUID()),
                publicCustomData: header.publicCustomData
            ),
            innerHeader: content.innerHeader
        )
    }

    @Test("Unknown KDF throws unsupportedKDF from the eager writer, not a process abort")
    func unknownKDFThrowsEager() throws {
        let content = withUnknownKDF(KDBXContent.makeEmpty(databaseName: "K", kdf: Self.cheapKDF))
        #expect(throws: KDBXWriter.Error.self) {
            try writeToMemory(content)
        }
    }

    @Test("Unknown KDF throws unsupportedKDF from the streaming writer, not a process abort")
    func unknownKDFThrowsStreaming() throws {
        let content = withUnknownKDF(KDBXContent.makeEmpty(databaseName: "K", kdf: Self.cheapKDF))
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }
        #expect(throws: KDBXWriter.Error.self) {
            try KDBXWriter.streamingWrite(
                to: outURL,
                content: content,
                binaries: [],
                unlockData: UnlockData(masterPassword: "pw")
            )
        }
    }

    @Test("A resolvable ref with a matching source still writes")
    func validRefStillWrites() throws {
        var content = makeContent(binaries: [.init(key: "a.bin", value: .ref(0))])
        let payload = Data([1, 2, 3, 4])
        content.innerHeader.binaryContent = [.init(shouldBeProtected: false, data: payload)]

        // Eager.
        try writeToMemory(content)

        // Streaming.
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }
        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: [DataBinarySource(payload, shouldBeProtected: false)],
            unlockData: UnlockData(masterPassword: "pw")
        )
    }
}
