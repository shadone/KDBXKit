//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CZlib
import Foundation

/// Push-based gzip *inflate* — the read-side mirror of ``GzipStreamWriter``.
/// Callers push compressed chunks via ``consume(_:)``; it inflates them
/// incrementally and forwards decompressed output **in ≤64 KiB chunks** to
/// `downstream`. Holding only a 64 KiB output window (never the whole
/// decompressed payload) is what lets the downstream consumer discard a
/// large binary pool without it ever being resident — the point of the
/// streaming read path.
///
/// `maxOutputBytes` caps cumulative output and throws
/// `ZlibError.outputTooLarge` mid-stream, matching the one-shot
/// ``GzipStreamReader``.
final class StreamingInflateReader: StreamingByteConsumer {
    private var stream = z_stream()
    private let downstream: any StreamingByteConsumer
    private let maxOutputBytes: Int
    private var producedTotal = 0
    private var streamEnded = false
    private var initialized = false

    init(downstream: any StreamingByteConsumer, maxOutputBytes: Int) throws {
        self.downstream = downstream
        self.maxOutputBytes = maxOutputBytes
        let status = inflateInit2_(
            &stream,
            47, // wBits: 15 + 32 → autodetect gzip / zlib (matches GzipStreamReader)
            ZLIB_VERSION,
            Int32(MemoryLayout<z_stream>.size)
        )
        guard status == Z_OK else { throw ZlibError.inflateInit(status) }
        initialized = true
    }

    deinit {
        if initialized { inflateEnd(&stream) }
    }

    func consume(_ chunk: Data) throws {
        guard !chunk.isEmpty, !streamEnded else { return }
        let bufferSize = 64 * 1024
        var output = [UInt8](repeating: 0, count: bufferSize)

        try chunk.withUnsafeBytes { (inputPtr: UnsafeRawBufferPointer) in
            let inputBase = inputPtr.bindMemory(to: UInt8.self).baseAddress
            stream.next_in = UnsafeMutablePointer<UInt8>(mutating: inputBase)
            stream.avail_in = UInt32(chunk.count)

            while true {
                let (status, produced): (Int32, Int) = try output.withUnsafeMutableBufferPointer { outBuf in
                    stream.next_out = outBuf.baseAddress
                    stream.avail_out = UInt32(bufferSize)
                    let s = inflate(&stream, Z_NO_FLUSH)
                    if s < 0, s != Z_BUF_ERROR {
                        throw ZlibError.inflate(s)
                    }
                    return (s, bufferSize - Int(stream.avail_out))
                }

                if produced > 0 {
                    producedTotal += produced
                    if producedTotal > maxOutputBytes {
                        throw ZlibError.outputTooLarge(limit: maxOutputBytes)
                    }
                    try downstream.consume(Data(output[0..<produced]))
                }

                if status == Z_STREAM_END {
                    streamEnded = true
                    break
                }
                // avail_out > 0 means inflate ran out of input to make more
                // progress — wait for the next chunk.
                if stream.avail_out != 0 {
                    break
                }
            }
        }
    }

    func finalize() throws {
        // KDBX gzip streams terminate within the block data, so by the time
        // the last block is consumed `inflate` has reported Z_STREAM_END.
        // A stream that never ended means the payload was truncated.
        guard streamEnded else { throw ZlibError.truncatedInput }
        try downstream.finalize()
    }
}
