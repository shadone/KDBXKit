//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Malformed-input behavior of the streaming inner-header parsers. These
/// run behind the block-stream HMAC (own credentials), but a hostile or
/// buggy writer must still produce typed errors — never a silent
/// one-byte desync or an unbounded buffer.
@Suite("Streaming inner-header parsing — hostile TLV records")
struct InnerHeaderStreamConsumerTests {
    private func tlv(_ type: UInt8, length: UInt32, value: [UInt8] = []) -> Data {
        var record = Data([type])
        record.append(contentsOf: [
            UInt8(length & 0xFF),
            UInt8((length >> 8) & 0xFF),
            UInt8((length >> 16) & 0xFF),
            UInt8((length >> 24) & 0xFF),
        ])
        record.append(contentsOf: value)
        return record
    }

    /// A `binaryContent` record's value is `flags(1) ‖ payload`, so a
    /// zero-length value is malformed — there is no flags byte. The eager
    /// reader throws; the streaming parsers used to consume one byte of
    /// the NEXT record as the flags byte, desyncing all later parsing.
    @Test("Zero-length binaryContent TLV throws in the XML stream consumer")
    func zeroLengthBinaryThrowsInConsumer() {
        let consumer = InnerHeaderXMLStreamConsumer()
        var stream = tlv(3, length: 0)
        stream.append(tlv(0, length: 0)) // end-of-header
        #expect(throws: KDBXReader.Error.self) {
            try consumer.consume(stream)
        }
    }

    @Test("Zero-length binaryContent TLV throws in the single-binary extractor")
    func zeroLengthBinaryThrowsInExtractor() {
        let extractor = StreamingBinaryExtractor(targetIndex: 0) { _ in }
        var stream = tlv(3, length: 0)
        stream.append(tlv(0, length: 0))
        #expect(throws: KDBXReader.Error.self) {
            try extractor.consume(stream)
        }
    }

    /// Non-binary fields buffer whole before parsing. Legitimate inner-
    /// header fields are tiny (algorithm ID, a 64-byte key); a declared
    /// multi-hundred-MB length must be rejected up front, not accumulated
    /// into `pending` — the streaming path exists precisely to bound
    /// memory in the jetsam-capped AutoFill extension.
    @Test("A huge small-field length is rejected up front in the XML stream consumer")
    func hugeSmallFieldLengthThrowsInConsumer() {
        let consumer = InnerHeaderXMLStreamConsumer()
        let stream = tlv(2, length: 500_000_000)
        #expect(throws: KDBXReader.Error.self) {
            try consumer.consume(stream)
        }
    }

    @Test("A huge small-field length is rejected up front in the single-binary extractor")
    func hugeSmallFieldLengthThrowsInExtractor() {
        let extractor = StreamingBinaryExtractor(targetIndex: 0) { _ in }
        let stream = tlv(2, length: 500_000_000)
        #expect(throws: KDBXReader.Error.self) {
            try extractor.consume(stream)
        }
    }

    /// KeePass defines bit 0x01 as "protect"; other bits are reserved. A
    /// writer setting a reserved bit alongside it must not flip the
    /// binary to unprotected.
    @Test("Protected flag is a bit test, not strict equality — streaming consumer")
    func protectedFlagBitTestStreaming() throws {
        let consumer = InnerHeaderXMLStreamConsumer()
        var stream = tlv(1, length: 4, value: [3, 0, 0, 0]) // ChaCha20
        stream.append(tlv(2, length: 64, value: [UInt8](repeating: 0x11, count: 64)))
        stream.append(tlv(3, length: 9, value: [0x03] + [UInt8](repeating: 0xAA, count: 8)))
        stream.append(tlv(0, length: 0))
        try consumer.consume(stream)
        try consumer.finalize()
        try #require(consumer.binaries.count == 1)
        #expect(consumer.binaries[0].isProtected)
    }

    @Test("Protected flag is a bit test, not strict equality — eager reader")
    func protectedFlagBitTestEager() throws {
        var data = tlv(1, length: 4, value: [3, 0, 0, 0])
        data.append(tlv(2, length: 64, value: [UInt8](repeating: 0x11, count: 64)))
        data.append(tlv(3, length: 9, value: [0x03] + [UInt8](repeating: 0xAA, count: 8)))
        data.append(tlv(0, length: 0))
        var reader = InnerHeaderReader(data: data)
        let innerHeader = try reader.parse().header
        try #require(innerHeader.binaryContent.count == 1)
        #expect(innerHeader.binaryContent[0].shouldBeProtected)
    }
}
