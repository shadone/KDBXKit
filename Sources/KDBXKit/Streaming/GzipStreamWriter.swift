//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Compression
import Foundation

/// Streaming gzip compressor. Apple's `Compression` framework
/// `OutputFilter(.compress, using: .zlib, …)` emits **raw deflate**
/// bytes (despite the algorithm being named `.zlib` — that's the
/// library identifier, not the wrapper format). To turn raw deflate
/// into gzip, prepend the 10-byte gzip header and append the 8-byte
/// trailer (CRC32 of uncompressed data + uncompressed length mod
/// 2^32). Deflate bytes themselves are forwarded unchanged.
///
/// CRC32 is computed incrementally over the uncompressed bytes;
/// uncompressed size is the running byte count.
internal final class GzipStreamWriter: StreamingByteConsumer {
    private static let gzipHeader: [UInt8] = [
        0x1F, 0x8B, // magic
        0x08,       // CM = deflate
        0x00,       // FLG = none
        0x00, 0x00, 0x00, 0x00, // MTIME = 0
        0x00,       // XFL = 0
        0xFF        // OS = unknown
    ]

    private let downstream: any StreamingByteConsumer
    private var filter: OutputFilter!
    private var crc32 = CRC32()
    private var uncompressedSize: UInt64 = 0
    /// First chunk: emit the gzip header before forwarding deflate
    /// bytes.
    private var headerEmitted = false

    init(downstream: any StreamingByteConsumer) throws {
        self.downstream = downstream
        // OutputFilter calls the closure synchronously inside
        // .write() / .finalize(), so we can capture self by unowned
        // reference safely.
        self.filter = try OutputFilter(.compress, using: .zlib, bufferCapacity: 65536) { [weak self] chunk in
            guard let self else { return }
            if let chunk {
                // Errors thrown by the downstream chain bubble up via
                // `pendingError`; OutputFilter's closure can't throw.
                self.handleDeflateBytes(chunk)
            }
        }
    }

    private var pendingError: Error?

    func consume(_ chunk: Data) throws {
        crc32.update(chunk)
        uncompressedSize &+= UInt64(chunk.count)
        try filter.write(chunk)
        if let err = pendingError {
            pendingError = nil
            throw err
        }
    }

    func finalize() throws {
        try filter.finalize()
        if let err = pendingError {
            pendingError = nil
            throw err
        }

        // Emit gzip footer: CRC32 LE + uncompressed-size LE (mod 2^32).
        let crc = crc32.finalized
        let isize = UInt32(uncompressedSize & 0xFFFFFFFF)
        var footer = Data()
        footer.append(contentsOf: crc.leBytes)
        footer.append(contentsOf: isize.leBytes)
        try downstream.consume(footer)
        try downstream.finalize()
    }

    private func handleDeflateBytes(_ data: Data) {
        do {
            if !headerEmitted {
                try downstream.consume(Data(Self.gzipHeader))
                headerEmitted = true
            }
            if !data.isEmpty {
                try downstream.consume(data)
            }
        } catch {
            pendingError = error
        }
    }
}

private extension FixedWidthInteger {
    var leBytes: [UInt8] {
        withUnsafeBytes(of: self.littleEndian) { Array($0) }
    }
}
