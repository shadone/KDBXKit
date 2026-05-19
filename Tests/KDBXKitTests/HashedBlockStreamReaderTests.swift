//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Focused tests for the KDBX 3.x hashed block stream framing.
///
/// End-to-end 3.1 read coverage in `StaticReaderAPITests` exercises this
/// reader, but a failure there can land in any of ~10 layers above
/// (header, KDF, AES-CBC, StreamStartBytes, hashed stream, gunzip, XML).
/// These tests isolate the block-stream layer with hand-built inputs so
/// regressions surface at the framing boundary directly.
@Suite("HashedBlockStreamReader")
struct HashedBlockStreamReaderTests {
    /// Encode a payload as a sequence of hashed-stream blocks. Used by
    /// the tests below to produce known-good inputs. Mirrors the writer
    /// shape KeePass 2.x uses: one block per chunk + a zero-length
    /// terminator at the end.
    private static func encode(_ chunks: [Data]) -> Data {
        var out = Data()
        for (i, chunk) in chunks.enumerated() {
            out.append(UInt32(i).toDataLittleEndian())
            out.append(chunk.sha256())
            out.append(UInt32(chunk.count).toDataLittleEndian())
            out.append(chunk)
        }
        // Terminator: blockId (any) + 32 hash bytes (ignored) + size=0.
        out.append(UInt32(chunks.count).toDataLittleEndian())
        out.append(Data(repeating: 0, count: 32))
        out.append(UInt32(0).toDataLittleEndian())
        return out
    }

    @Test("Single-block stream decodes to the original payload")
    func decodesSingleBlock() throws {
        let payload = Data("hello, kdbx 3.x".utf8)
        let encoded = Self.encode([payload])

        let decoded = try HashedBlockStreamReader.decode(encoded)
        #expect(decoded == payload)
    }

    @Test("Multi-block stream decodes into the concatenated payload in order")
    func concatenatesBlocks() throws {
        let chunks = [
            Data("alpha".utf8),
            Data(repeating: 0x42, count: 1024),
            Data("ω final".utf8),
        ]
        let encoded = Self.encode(chunks)

        let decoded = try HashedBlockStreamReader.decode(encoded)
        let expected = chunks.reduce(Data(), +)
        #expect(decoded == expected)
    }

    @Test("Empty payload (terminator only) decodes to an empty Data")
    func terminatorOnly() throws {
        let encoded = Self.encode([])

        let decoded = try HashedBlockStreamReader.decode(encoded)
        #expect(decoded.isEmpty)
    }

    @Test("Terminator hash bytes are not validated — any 32 bytes accepted")
    func terminatorHashIsAdvisory() throws {
        // KeePass's writer emits 32 zero bytes for the terminator hash
        // by convention, but the value has nothing to authenticate
        // (size=0 means no payload). The reader must tolerate any
        // hash bytes so future writers that pick a different
        // convention (e.g. SHA-256 of the empty string) keep working.
        var encoded = Self.encode([])
        // Overwrite the terminator hash with garbage. Layout:
        // blockId (4) + hash (32) + size (4).
        let hashStart = encoded.startIndex.advanced(by: 4)
        let hashEnd = hashStart.advanced(by: 32)
        encoded.replaceSubrange(hashStart..<hashEnd, with: Data(repeating: 0xFF, count: 32))

        let decoded = try HashedBlockStreamReader.decode(encoded)
        #expect(decoded.isEmpty)
    }

    @Test("Tampered block payload trips blockHashMismatch with the right index")
    func detectsCorruptedPayload() throws {
        let chunks = [Data("untouched".utf8), Data("victim".utf8)]
        var encoded = Self.encode(chunks)

        // Flip a byte inside the second block's payload. Block layout:
        // block 0: 4 (id) + 32 (hash) + 4 (size) + 9 (payload) = 49 bytes
        // block 1: starts at offset 49; payload starts at 49+40 = 89.
        let victimByteOffset = 49 + 4 + 32 + 4
        encoded[encoded.startIndex.advanced(by: victimByteOffset)] ^= 0x01

        do {
            _ = try HashedBlockStreamReader.decode(encoded)
            Issue.record("Expected blockHashMismatch")
        } catch let error as HashedBlockStreamReader.Error {
            if case let .blockHashMismatch(blockIndex) = error {
                #expect(blockIndex == 1)
            } else {
                Issue.record("Wrong error: \(error)")
            }
        }
    }

    @Test("Tampered hash bytes also trip blockHashMismatch")
    func detectsCorruptedHash() throws {
        let chunks = [Data("payload".utf8)]
        var encoded = Self.encode(chunks)

        // Flip a byte in the first block's stored hash.
        let hashByteOffset = 4 + 1
        encoded[encoded.startIndex.advanced(by: hashByteOffset)] ^= 0xFF

        #expect(throws: HashedBlockStreamReader.Error.blockHashMismatch(blockIndex: 0)) {
            try HashedBlockStreamReader.decode(encoded)
        }
    }

    @Test("Truncated input throws unexpectedEOF")
    func detectsTruncatedHeader() throws {
        // A complete block header is 40 bytes (blockId + hash + size).
        // Anything shorter than that on the first read trips the EOF
        // guard.
        let truncated = Data(repeating: 0, count: 39)
        #expect(throws: HashedBlockStreamReader.Error.unexpectedEOF) {
            try HashedBlockStreamReader.decode(truncated)
        }
    }

    @Test("Truncated block payload (size declares more bytes than remain) throws unexpectedEOF")
    func detectsTruncatedPayload() throws {
        // Announce a 100-byte block but provide only 10 bytes after
        // the header. The reader's bounds check fires before the
        // SHA-256 compare.
        var encoded = Data()
        encoded.append(UInt32(0).toDataLittleEndian())
        encoded.append(Data(repeating: 0, count: 32))
        encoded.append(UInt32(100).toDataLittleEndian())
        encoded.append(Data(repeating: 0xAA, count: 10))

        #expect(throws: HashedBlockStreamReader.Error.unexpectedEOF) {
            try HashedBlockStreamReader.decode(encoded)
        }
    }
}
