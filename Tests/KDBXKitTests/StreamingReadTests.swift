//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

/// `openMetadataStreaming` must be byte-for-byte equivalent to the eager
/// `parse` / `openMetadataOnly` — same database, same per-binary metadata,
/// same on-demand bytes — while never materializing the binary pool. These
/// tests exercise both ciphers, compression, and binary sizes that cross the
/// 64 KiB inflate-chunk and 1 MiB HMAC-block boundaries the streaming state
/// machine has to span.
@Suite("KDBXReader streaming metadata open")
struct StreamingReadTests {
    private func fixtureURL(_ name: String) -> URL {
        URL(filePath: Bundle.module.path(forResource: "Resources/\(name)", ofType: "kdbx")!)
    }

    private func randomData(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    /// Write `binaries` as the inner-header pool over `baseName`'s content
    /// (inheriting its cipher + KDF + compression), returning the file bytes.
    private func writeVault(baseName: String, password: String, binaries: [Data]) throws -> Data {
        var base = try KDBXReader.parse(
            try Data(contentsOf: fixtureURL(baseName)),
            unlockData: .init(masterPassword: password)
        )
        let out = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        defer { try? FileManager.default.removeItem(at: out) }
        // The inner header must carry the pool shape the sources fill —
        // the writer refuses a sources/pool count mismatch.
        base.innerHeader.binaryContent = binaries.map { .init(shouldBeProtected: false, data: $0) }
        let sources: [any BinarySource] = binaries.map { DataBinarySource($0, shouldBeProtected: false) }
        try KDBXWriter.streamingWrite(
            to: out,
            content: base,
            binaries: sources,
            unlockData: .init(masterPassword: password),
            regenerateSalts: false
        )
        return try Data(contentsOf: out)
    }

    /// Assert the streaming open of `data` matches the eager parse exactly.
    /// The streaming open goes through a temp `.file` source so the
    /// memory-mapped read path (`readAll(mappedIfSafe:)`) is exercised too.
    private func assertStreamingMatchesEager(
        _ data: Data,
        password: String,
        expectedBinaries: [Data]
    ) throws {
        let eager = try KDBXReader.parse(data, unlockData: .init(masterPassword: password))

        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        try data.write(to: fileURL)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let streaming = try KDBXReader.openMetadataStreaming(
            from: .file(fileURL),
            unlockData: .init(masterPassword: password)
        )

        // Whole parsed database is identical.
        #expect(streaming.database == eager.database)
        // Streaming never retains binary bytes.
        #expect(streaming.innerHeader.binaryContent.isEmpty)

        try #require(streaming.binaries.count == eager.innerHeader.binaryContent.count)
        try #require(streaming.binaries.count == expectedBinaries.count)

        for (i, eagerBin) in eager.innerHeader.binaryContent.enumerated() {
            let meta = streaming.binaries[i]
            #expect(meta.sizeBytes == eagerBin.data.count, "binary \(i) size")
            #expect(meta.isProtected == eagerBin.shouldBeProtected, "binary \(i) protected flag")
            #expect(meta.contentHash == Data(SHA256.hash(data: eagerBin.data)), "binary \(i) hash")

            // streamBinary off the streaming content re-resolves the bytes.
            var sink = DataSink()
            try KDBXReader.streamBinary(from: streaming, at: i, into: &sink)
            #expect(sink.data == eagerBin.data, "binary \(i) streamed bytes")
            #expect(sink.data == expectedBinaries[i], "binary \(i) vs original")
        }
    }

    // Sizes chosen to span boundaries: empty, single byte, > one 64 KiB
    // inflate chunk, > one 1 MiB HMAC block, and several blocks.
    private var boundarySpanningBinaries: [Data] {
        [
            Data(),
            Data([0x42]),
            randomData(200 * 1024),
            randomData(1_500_000),
            randomData(3_000_000),
        ]
    }

    @Test("Streaming == eager — AES-256-CBC, boundary-spanning binaries")
    func aesCBC_boundarySpanning() throws {
        let binaries = boundarySpanningBinaries
        let data = try writeVault(baseName: "simple-argon2id-aes256", password: "123", binaries: binaries)
        try assertStreamingMatchesEager(data, password: "123", expectedBinaries: binaries)
    }

    @Test("Streaming == eager — ChaCha20, boundary-spanning binaries")
    func chaCha20_boundarySpanning() throws {
        let binaries = boundarySpanningBinaries
        let data = try writeVault(baseName: "Format400", password: "t", binaries: binaries)
        try assertStreamingMatchesEager(data, password: "t", expectedBinaries: binaries)
    }

    @Test("Streaming == eager — vault with no binaries")
    func noBinaries() throws {
        let data = try Data(contentsOf: fixtureURL("simple-argon2id-aes256"))
        let eager = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        let streaming = try KDBXReader.openMetadataStreaming(
            from: .data(data),
            unlockData: .init(masterPassword: "123")
        )
        #expect(streaming.database == eager.database)
        #expect(streaming.binaries.isEmpty)
        #expect(eager.innerHeader.binaryContent.isEmpty)
    }

    @Test("Streaming == eager — real fixture with attachments (kpxc-extras)")
    func realFixtureWithAttachments() throws {
        let data = try Data(contentsOf: fixtureURL("kpxc-extras"))
        let eager = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))
        let streaming = try KDBXReader.openMetadataStreaming(
            from: .data(data),
            unlockData: .init(masterPassword: "test")
        )
        #expect(streaming.database == eager.database)
        try #require(streaming.binaries.count == eager.innerHeader.binaryContent.count)
        for (i, eagerBin) in eager.innerHeader.binaryContent.enumerated() {
            let meta = streaming.binaries[i]
            #expect(meta.sizeBytes == eagerBin.data.count)
            #expect(meta.contentHash == Data(SHA256.hash(data: eagerBin.data)))
            var sink = DataSink()
            try KDBXReader.streamBinary(from: streaming, at: i, into: &sink)
            #expect(sink.data == eagerBin.data)
        }
    }

    @Test("Streaming rejects wrong credentials")
    func wrongCredentials() throws {
        let data = try Data(contentsOf: fixtureURL("simple-argon2id-aes256"))
        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.openMetadataStreaming(
                from: .data(data),
                unlockData: .init(masterPassword: "wrong-password")
            )
        }
    }

    // MARK: - streamBinary single-binary extractor

    /// `streamBinary` must size-independently extract any one binary
    /// regardless of how the `LazyKDBXContent` was opened. Here the lazy
    /// content comes from the NON-streaming `openMetadataOnly` open, so the
    /// extractor path is proven independent of its metadata source.
    @Test("streamBinary extracts each binary from an openMetadataOnly lazy")
    func streamBinaryFromMetadataOnly() throws {
        let binaries = boundarySpanningBinaries
        let data = try writeVault(baseName: "simple-argon2id-aes256", password: "123", binaries: binaries)
        let lazy = try KDBXReader.openMetadataOnly(from: .data(data), unlockData: .init(masterPassword: "123"))
        try #require(lazy.binaries.count == binaries.count)
        for (i, expected) in binaries.enumerated() {
            var sink = DataSink(capacityHint: lazy.binaries[i].sizeBytes)
            try KDBXReader.streamBinary(from: lazy, at: i, into: &sink)
            #expect(sink.data == expected, "binary \(i)")
        }
    }

    /// The extractor feeds whatever sink the caller supplies. Prove a
    /// non-`DataSink` (the page-locked protected-bytes sink) receives the
    /// exact bytes, since that's the AutoFill-relevant path.
    @Test("streamBinary into SecureBytesSink yields exact bytes")
    func streamBinaryIntoSecureBytesSink() throws {
        let binaries = [randomData(200 * 1024), randomData(1_500_000)]
        let data = try writeVault(baseName: "Format400", password: "t", binaries: binaries)
        let lazy = try KDBXReader.openMetadataStreaming(from: .data(data), unlockData: .init(masterPassword: "t"))
        for (i, expected) in binaries.enumerated() {
            var sink = SecureBytesSink(capacityHint: lazy.binaries[i].sizeBytes)
            try KDBXReader.streamBinary(from: lazy, at: i, into: &sink)
            let secure = sink.takeSecureBytes()
            let got = secure.withUnsafeBytes { Data($0.bindMemory(to: UInt8.self)) }
            #expect(got == expected, "binary \(i)")
        }
    }

    @Test("streamBinary rejects an out-of-range index")
    func streamBinaryOutOfRange() throws {
        let data = try writeVault(baseName: "simple-argon2id-aes256", password: "123", binaries: [randomData(1024)])
        let lazy = try KDBXReader.openMetadataStreaming(from: .data(data), unlockData: .init(masterPassword: "123"))
        var sink = DataSink()
        #expect(throws: KDBXReader.Error.self) {
            try KDBXReader.streamBinary(from: lazy, at: 5, into: &sink)
        }
    }
}
