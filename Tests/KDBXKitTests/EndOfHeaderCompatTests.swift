//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing

@testable import KDBXKit

/// The outer header's end-of-header field (type 0) carries a value that
/// implementations disagree about.
///
/// KeePass 2.x, KeePassXC and KeePassium all write `\r\n\r\n`. Some other
/// implementation writes an empty value — KDBX 4.0 files carrying one turn up
/// in the wild. A reader that insists on `\r\n\r\n` cannot open them, even
/// though they are valid in every other respect.
///
/// Rejecting a non-standard marker also buys nothing: the header bytes are
/// covered by the header SHA-256 digest and the HMAC, so tampering is detected
/// regardless of what this field contains.
struct EndOfHeaderCompatTests {
    /// A representative KDBX 4.1 header, serialized to bytes.
    private func headerBytes() throws -> Data {
        let header = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: .AES256CBC,
            compressionAlgorithm: .gzip,
            masterSalt: Data(repeating: 0x11, count: 32),
            encryptionNonce: Data(repeating: 0x22, count: 16),
            kdfParameters: .argon2id(
                .init(
                    version: .v1_3,
                    salt: Data(repeating: 0x33, count: 32),
                    iterations: 2,
                    memory: 1 << 20,
                    parallelism: 2
                ),
                additional: [:]
            ),
            publicCustomData: [:]
        )

        let stream = OutputStream(toMemory: ())
        stream.open()
        try HeaderWriter(to: stream).write(header)
        return stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
    }

    /// Replace the trailing end-of-header TLV with one carrying `value`.
    ///
    /// The writer emits end-of-header last, as `type(1) + length(4) + 4 bytes`,
    /// so dropping the final 9 bytes removes exactly that field.
    private func replacingEndOfHeader(_ data: Data, with value: Data) -> Data {
        var rewritten = data.dropLast(9)
        rewritten.append(0x00)
        rewritten.append(contentsOf: UInt32(value.count).toDataLittleEndian())
        rewritten.append(contentsOf: value)
        return Data(rewritten)
    }

    @Test("the conventional \\r\\n\\r\\n marker still parses")
    func conventionalMarker() throws {
        var reader = HeaderReader(data: try headerBytes())
        let (parsed, _) = try reader.parse()
        #expect(parsed.formatVersion == .v4_1)
    }

    @Test("an empty end-of-header value parses")
    func emptyMarker() throws {
        // The exact shape found in real KDBX 4.0 files. Before this change it
        // threw `corrupted(reason: "Invalid end-of-header value...")`, which
        // made those vaults unreadable.
        let patched = replacingEndOfHeader(try headerBytes(), with: Data())

        var reader = HeaderReader(data: patched)
        let (parsed, length) = try reader.parse()

        #expect(parsed.formatVersion == .v4_1)
        #expect(parsed.encryptionAlgorithm == .AES256CBC)
        #expect(parsed.masterSalt == Data(repeating: 0x11, count: 32))
        #expect(length == patched.count)
    }

    @Test("an arbitrary end-of-header value parses")
    func arbitraryMarker() throws {
        // Nothing in the format assigns this field meaning, so a reader should
        // not care what a writer chose to put there.
        let patched = replacingEndOfHeader(
            try headerBytes(),
            with: Data("KeePassX".utf8)
        )

        var reader = HeaderReader(data: patched)
        let (parsed, _) = try reader.parse()
        #expect(parsed.formatVersion == .v4_1)
    }

    @Test("the rest of the header is still validated")
    func stillValidatesRealCorruption() throws {
        // Loosening the marker check must not loosen anything else: a header
        // that ends before its fields are complete is still corrupt.
        let truncated = Data(try headerBytes().prefix(20))

        var reader = HeaderReader(data: truncated)
        #expect(throws: HeaderReader.Error.self) {
            _ = try reader.parse()
        }
    }
}
