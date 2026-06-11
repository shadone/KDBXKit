//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

/// Memory-regression guard for the streaming metadata open. The whole point
/// of ``InnerHeaderXMLStreamConsumer`` is that binary-pool payloads drain
/// straight through the SHA-256 hasher and are never buffered — so peak
/// memory tracks the XML size plus a small window, NOT the attachment bytes.
///
/// The byte-correctness tests (``StreamingReadTests``) would still pass if a
/// regression silently buffered each binary, so they can't catch that. This
/// suite drives the consumer directly with a synthetic inner stream carrying
/// a multi-megabyte binary in 64 KiB chunks and asserts the work buffer
/// (`peakPendingBytes`) stays a small window — failing loudly if anyone
/// reintroduces per-binary accumulation.
@Suite("Streaming consumer buffer bound")
struct StreamingConsumerBufferTests {
    private func tlv(_ type: UInt8, _ value: [UInt8]) -> [UInt8] {
        let len = UInt32(value.count)
        return [
            type,
            UInt8(len & 0xFF),
            UInt8((len >> 8) & 0xFF),
            UInt8((len >> 16) & 0xFF),
            UInt8((len >> 24) & 0xFF),
        ] + value
    }

    private func int32LE(_ v: Int32) -> [UInt8] {
        let u = UInt32(bitPattern: v)
        return [UInt8(u & 0xFF), UInt8((u >> 8) & 0xFF), UInt8((u >> 16) & 0xFF), UInt8((u >> 24) & 0xFF)]
    }

    @Test("A multi-MB binary never inflates the work buffer")
    func largeBinaryDoesNotBufferUp() throws {
        // Synthetic decompressed inner stream: cipher fields, one 5 MiB
        // unprotected binary, end-of-header, then a small XML body.
        let payload = [UInt8](repeating: 0x7E, count: 5 * 1024 * 1024)
        let xmlBody = Array("<KeePassFile><Root/></KeePassFile>".utf8)

        var stream: [UInt8] = []
        stream += tlv(1, int32LE(InnerHeader.EncryptionAlgorithm.ChaCha20.rawValue)) // algorithm
        stream += tlv(2, [UInt8](repeating: 0xAB, count: 64)) // inner-stream key
        stream += tlv(3, [0x00] + payload) // binaryContent: flags(unprotected) + payload
        stream += tlv(0, []) // end-of-header
        stream += xmlBody // XML follows the header

        let consumer = InnerHeaderXMLStreamConsumer()
        let chunkSize = 64 * 1024
        var offset = 0
        while offset < stream.count {
            let end = min(offset + chunkSize, stream.count)
            try consumer.consume(Data(stream[offset..<end]))
            offset = end
        }
        try consumer.finalize()

        // Metadata captured correctly despite never buffering the payload.
        try #require(consumer.binaries.count == 1)
        #expect(consumer.binaries[0].sizeBytes == payload.count)
        #expect(consumer.binaries[0].isProtected == false)
        #expect(consumer.binaries[0].contentHash == Data(SHA256.hash(data: Data(payload))))
        #expect(consumer.xml == Data(xmlBody))

        let header = try consumer.makeInnerHeader()
        #expect(header.encryptionAlgorithm == .ChaCha20)
        #expect(header.binaryContent.isEmpty)

        // The guard: peak work buffer is a small window (~one chunk), NOT
        // the 5 MiB binary. If a regression buffered the payload this would
        // be in the megabytes.
        #expect(
            consumer.peakPendingBytes < 128 * 1024,
            "work buffer peaked at \(consumer.peakPendingBytes) bytes — binary pool is being buffered"
        )
    }
}
