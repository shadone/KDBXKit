//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("StreamingBinaryExtractor")
struct StreamingBinaryExtractorTests {
    /// TLV record: type=3 (binaryContent), little-endian length, flags byte.
    private func binaryRecordHeader(payloadLength: Int) -> Data {
        var record = Data([3])
        let length = UInt32(payloadLength + 1) // value = flags(1) + payload
        record.append(contentsOf: [
            UInt8(length & 0xFF),
            UInt8((length >> 8) & 0xFF),
            UInt8((length >> 16) & 0xFF),
            UInt8((length >> 24) & 0xFF),
        ])
        record.append(0) // flags
        return record
    }

    @Test("A stream ending mid-target throws instead of finalizing a truncated attachment")
    func truncatedTargetThrowsOnFinalize() throws {
        var received = Data()
        let extractor = StreamingBinaryExtractor(targetIndex: 0) { buf in
            received.append(contentsOf: buf)
        }

        // The record declares 100 payload bytes but the stream delivers 50.
        var stream = binaryRecordHeader(payloadLength: 100)
        stream.append(Data(repeating: 0xCD, count: 50))
        try extractor.consume(stream)

        #expect(extractor.found)
        #expect(!extractor.done)
        // Silent success here is data loss: a half-streamed attachment
        // would reach the sink as if it were complete.
        #expect(throws: KDBXReader.Error.self) {
            try extractor.finalize()
        }
    }

    @Test("A fully streamed target finalizes cleanly")
    func completeTargetFinalizes() throws {
        var received = Data()
        let extractor = StreamingBinaryExtractor(targetIndex: 0) { buf in
            received.append(contentsOf: buf)
        }

        var stream = binaryRecordHeader(payloadLength: 8)
        stream.append(Data(repeating: 0xAB, count: 8))
        try extractor.consume(stream)

        #expect(extractor.done)
        #expect(received == Data(repeating: 0xAB, count: 8))
        #expect(throws: Never.self) {
            try extractor.finalize()
        }
    }
}
