//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

@Suite("Streaming pipeline primitives")
struct StreamingPipelineTests {
    /// Sink that just collects all consumed bytes into a Data buffer.
    /// Used as the terminal layer in unit tests for the upstream
    /// transforms.
    final class CollectingSink: StreamingByteConsumer {
        var collected = Data()
        var finalized = false
        func consume(_ chunk: Data) throws { collected.append(chunk) }
        func finalize() throws { finalized = true }
    }

    @Test("HMACBlockStreamWriter writes empty terminator on empty input")
    func hmacBlock_empty() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        let unlockKey = SecureBytes(Data(repeating: 0x11, count: 32))
        let masterSalt = Data(repeating: 0x22, count: 32)
        let writer = HMACBlockStreamWriter(fileHandle: handle, masterSalt: masterSalt, unlockKey: unlockKey)
        try writer.finalize()
        try handle.close()
        let bytes = try Data(contentsOf: url)
        // 32 (HMAC) + 4 (size = 0) + 0 (block) = 36 bytes
        #expect(bytes.count == 36)
    }

    @Test("HMACBlockStreamWriter splits at 1 MB boundaries")
    func hmacBlock_chunkedToOneMB() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        let unlockKey = SecureBytes(Data(repeating: 0x11, count: 32))
        let masterSalt = Data(repeating: 0x22, count: 32)
        let writer = HMACBlockStreamWriter(fileHandle: handle, masterSalt: masterSalt, unlockKey: unlockKey)

        // 2.5 MB → expect 2 full blocks + 1 partial + terminator.
        let mb = 1_048_576
        try writer.consume(Data(repeating: 0xAB, count: mb))
        try writer.consume(Data(repeating: 0xCD, count: mb))
        try writer.consume(Data(repeating: 0xEF, count: mb / 2))
        try writer.finalize()
        try handle.close()

        let bytes = try Data(contentsOf: url)
        // 2 * (32 + 4 + 1MB) + (32 + 4 + 0.5MB) + (32 + 4 + 0) =
        // 2_097_224 + 524_324 + 36 = 2_621_584
        let expected = 2 * (32 + 4 + mb) + (32 + 4 + mb / 2) + 36
        #expect(bytes.count == expected)
    }

    @Test("GzipStreamWriter round-trip via GzipStreamReader")
    func gzip_roundtrip() throws {
        let collector = CollectingSink()
        let gzip = try GzipStreamWriter(downstream: collector)
        let payload = Data("hello, gzip world. ".utf8) +
            Data(repeating: 0x41, count: 100_000) // 100KB of A's
        try gzip.consume(payload.prefix(100))
        try gzip.consume(payload.dropFirst(100))
        try gzip.finalize()

        // Sanity: must look like a gzip stream.
        #expect(collector.collected.count >= 18) // 10 header + 8 footer
        #expect(collector.collected.prefix(2) == Data([0x1F, 0x8B]))

        let decompressed = try GzipStreamReader.decompress(collector.collected, maxOutputBytes: 1_000_000)
        #expect(decompressed == payload)
    }
}
