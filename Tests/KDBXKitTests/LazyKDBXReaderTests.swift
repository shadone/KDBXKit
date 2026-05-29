//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBXReader lazy / streaming API")
struct LazyKDBXReaderTests {
    private func fixtureURL(_ name: String) -> URL {
        URL(filePath: Bundle.module.path(forResource: "Resources/\(name)", ofType: "kdbx")!)
    }

    // MARK: - openMetadataOnly basic shape

    @Test("openMetadataOnly returns parsed XML + binary metadata without bytes")
    func openMetadataOnly_parses_database() throws {
        let url = fixtureURL("simple-argon2id-aes256")
        let lazy = try KDBXReader.openMetadataOnly(
            from: .file(url),
            unlockData: .init(masterPassword: "123")
        )
        #expect(lazy.header.formatVersion == .v4_0)
        #expect(lazy.database.meta.databaseName != nil)
        // InnerHeader is exposed but its binaryContent is empty by construction.
        #expect(lazy.innerHeader.binaryContent.isEmpty)
    }

    // MARK: - Round-trip parity vs eager parse

    @Test("Lazy binary metadata + streamBinary == eager binaryContent[i].data")
    func lazyMetadata_matches_eagerBytes() throws {
        // Pick a fixture that actually carries attachments.
        let url = fixtureURL("kpxc-extras")
        let data = try Data(contentsOf: url)
        let eager = try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))

        let lazy = try KDBXReader.openMetadataOnly(
            from: .data(data),
            unlockData: .init(masterPassword: "test")
        )

        try #require(eager.innerHeader.binaryContent.count == lazy.binaries.count)
        for (i, eagerBin) in eager.innerHeader.binaryContent.enumerated() {
            let meta = lazy.binaries[i]
            #expect(meta.sizeBytes == eagerBin.data.count)
            #expect(meta.isProtected == eagerBin.shouldBeProtected)
            // Content hash agrees with SHA-256 of the eager bytes.
            #expect(meta.contentHash == Data(SHA256.hash(data: eagerBin.data)))

            // Re-stream and verify byte-equal.
            var sink = DataSink()
            try KDBXReader.streamBinary(from: lazy, at: i, into: &sink)
            #expect(sink.data == eagerBin.data)
        }
    }

    // MARK: - .data vs .file source equivalence

    @Test(".data and .file sources produce identical metadata + streamed bytes")
    func data_vs_file_sources_agree() throws {
        let url = fixtureURL("kpxc-extras")
        let data = try Data(contentsOf: url)
        let unlock = UnlockData(masterPassword: "test")

        let viaData = try KDBXReader.openMetadataOnly(from: .data(data), unlockData: unlock)
        let viaFile = try KDBXReader.openMetadataOnly(from: .file(url), unlockData: unlock)

        #expect(viaData.binaries == viaFile.binaries)

        for i in viaData.binaries.indices {
            var sinkA = DataSink()
            var sinkB = DataSink()
            try KDBXReader.streamBinary(from: viaData, at: i, into: &sinkA)
            try KDBXReader.streamBinary(from: viaFile, at: i, into: &sinkB)
            #expect(sinkA.data == sinkB.data)
        }
    }

    // MARK: - ByteSink implementations

    @Test("DataSink accumulates the bytes")
    func dataSink_accumulates() throws {
        let url = fixtureURL("kpxc-extras")
        let lazy = try KDBXReader.openMetadataOnly(
            from: .file(url),
            unlockData: .init(masterPassword: "test")
        )
        guard !lazy.binaries.isEmpty else { return }
        var sink = DataSink(capacityHint: lazy.binaries[0].sizeBytes)
        try KDBXReader.streamBinary(from: lazy, at: 0, into: &sink)
        #expect(sink.data.count == lazy.binaries[0].sizeBytes)
        #expect(Data(SHA256.hash(data: sink.data)) == lazy.binaries[0].contentHash)
    }

    @Test("SecureBytesSink yields SecureBytes with matching content")
    func secureBytesSink_works() throws {
        let url = fixtureURL("kpxc-extras")
        let lazy = try KDBXReader.openMetadataOnly(
            from: .file(url),
            unlockData: .init(masterPassword: "test")
        )
        guard !lazy.binaries.isEmpty else { return }
        let meta = lazy.binaries[0]
        var sink = SecureBytesSink(capacityHint: meta.sizeBytes)
        try KDBXReader.streamBinary(from: lazy, at: 0, into: &sink)
        let bytes = sink.takeSecureBytes()
        let asData = bytes.withUnsafeBytes { Data($0.bindMemory(to: UInt8.self)) }
        #expect(asData.count == meta.sizeBytes)
        #expect(Data(SHA256.hash(data: asData)) == meta.contentHash)
    }

    @Test("URLSink streams bytes straight to a file")
    func urlSink_writesFile() throws {
        let url = fixtureURL("kpxc-extras")
        let lazy = try KDBXReader.openMetadataOnly(
            from: .file(url),
            unlockData: .init(masterPassword: "test")
        )
        guard !lazy.binaries.isEmpty else { return }
        let meta = lazy.binaries[0]
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-test-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: outURL) }

        var sink = try URLSink(writingTo: outURL)
        try KDBXReader.streamBinary(from: lazy, at: 0, into: &sink)

        let onDisk = try Data(contentsOf: outURL)
        #expect(onDisk.count == meta.sizeBytes)
        #expect(Data(SHA256.hash(data: onDisk)) == meta.contentHash)
    }

    // MARK: - Memory shape

    @Test("LazyKDBXContent does not retain binary bytes")
    func lazyKDBXContent_releases_binary_bytes() throws {
        // No direct way to measure heap retention in-process; assert
        // via shape: innerHeader.binaryContent is empty + binaries
        // metadata array has no Data members holding the payload.
        let url = fixtureURL("kpxc-extras")
        let lazy = try KDBXReader.openMetadataOnly(
            from: .file(url),
            unlockData: .init(masterPassword: "test")
        )
        #expect(lazy.innerHeader.binaryContent.isEmpty)
        // BinaryMetadata only carries contentHash (32 bytes) — the
        // payload bytes are not reachable from `lazy` without
        // streamBinary.
        for meta in lazy.binaries {
            #expect(meta.contentHash.count == 32)
        }
    }

    // MARK: - Error paths

    @Test("streamBinary throws on out-of-range index")
    func streamBinary_outOfRange_throws() throws {
        let url = fixtureURL("kpxc-extras")
        let lazy = try KDBXReader.openMetadataOnly(
            from: .file(url),
            unlockData: .init(masterPassword: "test")
        )
        var sink = DataSink()
        #expect(throws: KDBXReader.Error.self) {
            try KDBXReader.streamBinary(from: lazy, at: Int.max, into: &sink)
        }
    }

    @Test("openMetadataOnly on a non-KDBX file throws invalidFileSignature")
    func openMetadataOnly_nonKDBX_throws() throws {
        let bogus = Data("not a kdbx file at all".utf8)
        #expect(throws: KDBXReader.Error.invalidFileSignature) {
            _ = try KDBXReader.openMetadataOnly(
                from: .data(bogus),
                unlockData: .init(masterPassword: "anything")
            )
        }
    }

    // MARK: - Batched pool decrypt (withDecryptedBinaries)

    /// Build a vault carrying several distinct, non-trivial
    /// attachments and reopen it lazily. Returns the lazy handle plus
    /// the original payloads keyed by pool index.
    private func makeLazyVaultWithAttachments(
        count: Int = 8,
        password: String = "123"
    ) throws -> (lazy: LazyKDBXContent, payloads: [Data]) {
        var content = try KDBXReader.parse(
            try Data(contentsOf: fixtureURL("simple-argon2id-aes256")),
            unlockData: .init(masterPassword: password)
        )
        let payloads: [Data] = (0..<count).map { i in
            // Distinct length + content per index so a mis-sliced
            // binary can't accidentally match another.
            Data((0..<(4096 + i)).map { UInt8(($0 &+ i) & 0xFF) })
        }
        content.innerHeader.binaryContent = payloads.enumerated().map { i, p in
            .init(shouldBeProtected: i.isMultiple(of: 2), data: p)
        }

        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).kdbx")
        try KDBXWriter.streamingWrite(
            to: outURL,
            content: content,
            binaries: payloads.enumerated().map { i, p in
                DataBinarySource(p, shouldBeProtected: i.isMultiple(of: 2))
            },
            unlockData: .init(masterPassword: password),
            regenerateSalts: false
        )
        // Read the encrypted bytes back and drive the lazy reader from a
        // `.data` source so the file's lifetime can't race the on-demand
        // re-reads `streamBinary` / `withDecryptedBinaries` perform.
        let encrypted = try Data(contentsOf: outURL)
        try? FileManager.default.removeItem(at: outURL)

        let lazy = try KDBXReader.openMetadataOnly(
            from: .data(encrypted),
            unlockData: .init(masterPassword: password)
        )
        return (lazy, payloads)
    }

    @Test("withDecryptedBinaries resolves every pool binary in one decrypt — parity with streamBinary")
    func withDecryptedBinaries_parity() throws {
        let (lazy, payloads) = try makeLazyVaultWithAttachments()
        try #require(lazy.binaries.count == payloads.count)

        // Reference bytes via the single-shot API.
        var reference: [Data] = []
        for i in lazy.binaries.indices {
            var sink = DataSink()
            try KDBXReader.streamBinary(from: lazy, at: i, into: &sink)
            reference.append(sink.data)
        }

        // Batched: decrypt once, slice every binary out of the resident
        // payload.
        var batched: [Int: Data] = [:]
        try KDBXReader.withDecryptedBinaries(from: lazy) { resolve in
            for i in lazy.binaries.indices {
                batched[i] = try resolve(i)
            }
        }

        #expect(batched.count == payloads.count)
        for i in lazy.binaries.indices {
            #expect(batched[i] == reference[i], "binary \(i) bytes differ from streamBinary")
            #expect(batched[i] == payloads[i], "binary \(i) bytes differ from original")
        }
    }

    @Test("withDecryptedBinaries resolver rejects an out-of-range index")
    func withDecryptedBinaries_outOfRange_throws() throws {
        let (lazy, _) = try makeLazyVaultWithAttachments(count: 2)
        #expect(throws: KDBXReader.Error.self) {
            try KDBXReader.withDecryptedBinaries(from: lazy) { resolve in
                _ = try resolve(Int.max)
            }
        }
    }

    @Test("openMetadataOnly with wrong credentials throws wrongCredentials")
    func openMetadataOnly_wrongPassword_throws() throws {
        let url = fixtureURL("simple-argon2id-aes256")
        let data = try Data(contentsOf: url)
        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.openMetadataOnly(
                from: .data(data),
                unlockData: .init(masterPassword: "wrong-password")
            )
        }
    }
}
