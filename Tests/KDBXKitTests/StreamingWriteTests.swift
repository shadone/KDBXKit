//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoKit
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
            #expect(reread.innerHeader.binaryContent[i].data == content.innerHeader.binaryContent[i].data,
                    "binary \(i) bytes mismatch")
            #expect(reread.innerHeader.binaryContent[i].shouldBeProtected == content.innerHeader.binaryContent[i].shouldBeProtected,
                    "binary \(i) protected flag mismatch")
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

    private func entriesIn(_ database: KDBX) -> Int {
        var count = 0
        database.visitEntries(in: database.root.group) { _ in count += 1 }
        return count
    }
}
