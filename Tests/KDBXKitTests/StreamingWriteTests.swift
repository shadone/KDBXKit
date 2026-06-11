//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBXWriter.streamingWrite")
struct StreamingWriteTests {
    private func fixtureURL(_ name: String) -> URL {
        URL(filePath: Bundle.module.path(forResource: "Resources/\(name)", ofType: "kdbx")!)
    }

    @Test("Streaming write round-trips through the eager reader (no attachments)")
    func streamRoundTrip_noAttachments() throws {
        let url = fixtureURL("simple-argon2id-aes256")
        let data = try Data(contentsOf: url)
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))

        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }

        // Pool is empty for this fixture; binaries array is empty.
        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: [],
            unlockData: .init(masterPassword: "123"),
            regenerateSalts: false
        )

        let reread = try KDBXReader.parse(
            try Data(contentsOf: outURL),
            unlockData: .init(masterPassword: "123")
        )
        // Database content survives the round trip.
        #expect(reread.database.meta.databaseName == content.database.meta.databaseName)
        let originalEntryCount = entriesIn(content.database)
        let rewriteEntryCount = entriesIn(reread.database)
        #expect(originalEntryCount == rewriteEntryCount)
    }

    @Test("Streaming write preserves attachments byte-for-byte")
    func streamRoundTrip_withAttachments() throws {
        let url = fixtureURL("kpxc-extras")
        let data = try Data(contentsOf: url)
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))

        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }

        let binaries: [any BinarySource] = content.innerHeader.binaryContent.map { bin in
            DataBinarySource(bin.data, shouldBeProtected: bin.shouldBeProtected)
        }

        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: binaries,
            unlockData: .init(masterPassword: "test"),
            regenerateSalts: false
        )

        let reread = try KDBXReader.parse(
            try Data(contentsOf: outURL),
            unlockData: .init(masterPassword: "test")
        )

        try #require(reread.innerHeader.binaryContent.count == content.innerHeader.binaryContent.count)
        for i in content.innerHeader.binaryContent.indices {
            #expect(
                reread.innerHeader.binaryContent[i].data == content.innerHeader.binaryContent[i].data,
                "binary \(i) bytes mismatch"
            )
            #expect(
                reread.innerHeader.binaryContent[i].shouldBeProtected == content.innerHeader.binaryContent[i].shouldBeProtected,
                "binary \(i) protected flag mismatch"
            )
        }
    }

    @Test("Streaming write composes with LazyBinarySource — disk-to-disk transcode")
    func streamRoundTrip_viaLazySource() throws {
        let url = fixtureURL("kpxc-extras")
        let data = try Data(contentsOf: url)
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))

        // Open lazily to get a LazyKDBXContent backing the pool.
        let lazyContent = try KDBXReader.openMetadataOnly(
            from: .data(data),
            unlockData: .init(masterPassword: "test")
        )

        let binaries: [any BinarySource] = lazyContent.binaries.indices.map { i in
            LazyBinarySource(lazyContent, at: i)
        }

        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }

        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: binaries,
            unlockData: .init(masterPassword: "test"),
            regenerateSalts: false
        )

        let reread = try KDBXReader.parse(
            try Data(contentsOf: outURL),
            unlockData: .init(masterPassword: "test")
        )
        for i in content.innerHeader.binaryContent.indices {
            #expect(reread.innerHeader.binaryContent[i].data == content.innerHeader.binaryContent[i].data)
        }
    }

    @Test("Streaming write via a shared LazyBinaryCache is byte-identical to per-source streaming")
    func streamRoundTrip_viaSharedCache() throws {
        // Build a vault with several distinct attachments so the cache
        // serves more than one binary from a single decrypt.
        var content = try KDBXReader.parse(
            try Data(contentsOf: fixtureURL("simple-argon2id-aes256")),
            unlockData: .init(masterPassword: "123")
        )
        let payloads: [Data] = (0..<6).map { i in
            Data((0..<(2048 + i)).map { UInt8(($0 &+ i) & 0xFF) })
        }
        content.innerHeader.binaryContent = payloads.enumerated().map { i, p in
            .init(shouldBeProtected: i.isMultiple(of: 2), data: p)
        }

        // Seed an encrypted file, then reopen it lazily.
        let seedURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        try KDBXWriter.streamingWrite(
            to: seedURL,
            content: content,
            binaries: payloads.enumerated().map { i, p in
                DataBinarySource(p, shouldBeProtected: i.isMultiple(of: 2))
            },
            unlockData: .init(masterPassword: "123"),
            regenerateSalts: false
        )
        let encrypted = try Data(contentsOf: seedURL)
        try? FileManager.default.removeItem(at: seedURL)

        let lazyContent = try KDBXReader.openMetadataOnly(
            from: .data(encrypted),
            unlockData: .init(masterPassword: "123")
        )

        // Re-save through a SHARED cache (one decrypt for all sources).
        let cache = LazyBinaryCache(lazyContent)
        let cachedSources: [any BinarySource] = lazyContent.binaries.indices.map { i in
            LazyBinarySource(lazyContent, at: i, cache: cache)
        }
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }
        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: cachedSources,
            unlockData: .init(masterPassword: "123"),
            regenerateSalts: false
        )

        // Every attachment round-trips byte-for-byte through the cache.
        let reread = try KDBXReader.parse(
            try Data(contentsOf: outURL),
            unlockData: .init(masterPassword: "123")
        )
        try #require(reread.innerHeader.binaryContent.count == payloads.count)
        for i in payloads.indices {
            #expect(reread.innerHeader.binaryContent[i].data == payloads[i], "binary \(i) mismatch via cache")
        }
    }

    @Test("A failed streaming write leaves an existing destination intact")
    func failedWritePreservesDestination() throws {
        let url = fixtureURL("simple-argon2id-aes256")
        let data = try Data(contentsOf: url)
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let outURL = dir.appendingPathComponent("vault.kdbx")

        // A good save first — this is the vault a failed save must not destroy.
        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: [],
            unlockData: .init(masterPassword: "123")
        )
        let goodBytes = try Data(contentsOf: outURL)

        // Now a save that fails mid-stream while pulling a binary.
        var failing = content
        failing.innerHeader.binaryContent = [.init(shouldBeProtected: false, data: Data(count: 8))]
        #expect(throws: (any Error).self) {
            try KDBXWriter.streamingWrite(
                to: outURL,
                content: failing,
                binaries: [ThrowingBinarySource()],
                unlockData: .init(masterPassword: "123")
            )
        }

        // The destination still holds the previous vault, byte-for-byte,
        // and no partial temp file is left behind.
        #expect(try Data(contentsOf: outURL) == goodBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["vault.kdbx"])
    }

    @Test("Eager and streaming writers produce equivalent vaults for the same content")
    func eagerAndStreamingAreEquivalent() throws {
        // Build a content with attachments (protected and not), protected
        // strings, history, and custom data — the surface where a
        // serialization-level invariant could diverge between the two
        // writers. This is the regression net for the stale-lazyContent
        // class of bug, which a single writer's round-trip can't catch.
        var content = try KDBXReader.parse(
            try Data(contentsOf: fixtureURL("simple-argon2id-aes256")),
            unlockData: .init(masterPassword: "123")
        )
        let payloads: [Data] = [
            Data((0..<2048).map { UInt8($0 & 0xFF) }),
            Data("a short secret attachment".utf8),
            Data(),
        ]
        content.innerHeader.binaryContent = payloads.enumerated().map { i, p in
            .init(shouldBeProtected: i.isMultiple(of: 2), data: p)
        }
        var entry = KDBX.Entry(uuid: UUID())
        entry.strings = [
            .init(key: "Title", value: .regular("Equiv")),
            .init(key: "Password", value: .unprotected("p@ss-word")),
            .init(key: "TOTP", value: .unprotected("otpauth://x")),
        ]
        entry.binaries = [
            .init(key: "blob.bin", value: .ref(0)),
            .init(key: "note.txt", value: .ref(1)),
        ]
        entry.customData = [.init(key: "k", value: "v")]
        content.database.root.group.entries.append(entry)

        let unlock = UnlockData(masterPassword: "123")

        // Eager write.
        let eagerStream = OutputStream(toMemory: ())
        eagerStream.open()
        try KDBXWriter(to: eagerStream).write(content, unlockData: unlock, regenerateSalts: false)
        let eagerBytes = eagerStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        eagerStream.close()

        // Streaming write of the SAME content + binaries.
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: outURL) }
        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: payloads.enumerated().map { i, p in
                DataBinarySource(p, shouldBeProtected: i.isMultiple(of: 2))
            },
            unlockData: unlock,
            regenerateSalts: false
        )
        let streamingBytes = try Data(contentsOf: outURL)

        // Parse both and assert the full database + inner-header pool match.
        let fromEager = try KDBXReader.parse(eagerBytes, unlockData: unlock)
        let fromStreaming = try KDBXReader.parse(streamingBytes, unlockData: unlock)

        #expect(fromEager.database == fromStreaming.database)
        #expect(fromEager.innerHeader.binaryContent == fromStreaming.innerHeader.binaryContent)
        #expect(fromEager.header.encryptionAlgorithm == fromStreaming.header.encryptionAlgorithm)
        #expect(fromEager.header.compressionAlgorithm == fromStreaming.header.compressionAlgorithm)

        // The decrypted attachments and protected strings must match too.
        for i in payloads.indices {
            #expect(fromEager.innerHeader.binaryContent[i].data == fromStreaming.innerHeader.binaryContent[i].data)
            #expect(fromEager.innerHeader.binaryContent[i].shouldBeProtected
                == fromStreaming.innerHeader.binaryContent[i].shouldBeProtected)
        }
    }

    private struct ThrowingBinarySource: BinarySource {
        struct Boom: Error { }
        var sizeBytes: Int { 8 }
        var shouldBeProtected: Bool { false }
        func stream(into sink: inout some ByteSink) throws { throw Boom() }
    }

    private func entriesIn(_ database: KDBX) -> Int {
        var count = 0
        database.visitEntries(in: database.root.group) { _ in count += 1 }
        return count
    }
}
