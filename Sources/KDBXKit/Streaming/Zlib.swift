//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CZlib
import Foundation

/// Errors raised by the streaming gzip compressor / decompressor.
enum ZlibError: Swift.Error, Equatable {
    case deflateInit(Int32)
    case deflate(Int32)
    case inflateInit(Int32)
    case inflate(Int32)
    case truncatedInput
    case outputTooLarge(limit: Int)
}

/// Push-based streaming gzip compressor over system zlib. Initialized
/// with `wBits = 31` (15 + 16) so zlib emits a complete gzip-wrapped
/// stream (header + DEFLATE body + CRC32/ISIZE trailer) — no need for
/// us to assemble those parts ourselves.
final class GzipStreamWriter: StreamingByteConsumer {
    private var stream = z_stream()
    private let downstream: any StreamingByteConsumer
    private var initialized = false
    private var finalized = false
    private let outputBufferSize = 64 * 1024

    init(downstream: any StreamingByteConsumer) throws {
        self.downstream = downstream
        let status = deflateInit2_(
            &stream,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            31, // wBits: 15 + 16 → gzip wrapper, max window
            8, // memLevel (zlib default)
            Z_DEFAULT_STRATEGY,
            ZLIB_VERSION,
            Int32(MemoryLayout<z_stream>.size)
        )
        guard status == Z_OK else {
            throw ZlibError.deflateInit(status)
        }
        initialized = true
    }

    deinit {
        if initialized, !finalized {
            deflateEnd(&stream)
        }
    }

    func consume(_ chunk: Data) throws {
        guard !chunk.isEmpty else { return }
        try pump(chunk, flush: Z_NO_FLUSH)
    }

    func finalize() throws {
        try pump(Data(), flush: Z_FINISH)
        deflateEnd(&stream)
        finalized = true
        try downstream.finalize()
    }

    private func pump(_ input: Data, flush: Int32) throws {
        var output = [UInt8](repeating: 0, count: outputBufferSize)
        try input.withUnsafeBytes { (inputPtr: UnsafeRawBufferPointer) in
            // zlib reads input via stream.next_in / stream.avail_in. Pointer
            // is valid for the duration of this closure.
            let inputBase = inputPtr.bindMemory(to: UInt8.self).baseAddress
            stream.next_in = UnsafeMutablePointer<UInt8>(mutating: inputBase)
            stream.avail_in = UInt32(input.count)

            var noProgress = false
            repeat {
                let produced = try output.withUnsafeMutableBufferPointer { outBuf -> Int in
                    stream.next_out = outBuf.baseAddress
                    stream.avail_out = UInt32(outputBufferSize)

                    let status = deflate(&stream, flush)
                    // Z_OK = 0, Z_STREAM_END = 1, both fine. Z_BUF_ERROR is
                    // zlib's non-fatal "no progress possible" — it fires
                    // when the previous iteration's output exactly filled
                    // the buffer and all input is already consumed (the
                    // re-entry call has avail_in == 0). The inflate wrappers
                    // already treat it as a loop terminator; failing the
                    // save on it would be a spurious, fixture-dependent
                    // ~2^-16 deflate abort. Other negatives are errors.
                    if status == Z_BUF_ERROR {
                        noProgress = true
                        return outputBufferSize - Int(stream.avail_out)
                    }
                    if status < 0 {
                        throw ZlibError.deflate(status)
                    }
                    return outputBufferSize - Int(stream.avail_out)
                }
                if produced > 0 {
                    try downstream.consume(Data(output.prefix(produced)))
                }
                // Loop while zlib has more output to give us (output buffer
                // was completely filled). For Z_FINISH, also loop while
                // there's pending input to drain.
            } while stream.avail_out == 0 && !noProgress
        }
    }
}

/// One-shot collector that captures everything fed through a
/// `StreamingByteConsumer` chain into an in-memory `Data`.
private final class DataCollector: StreamingByteConsumer {
    var collected = Data()
    func consume(_ chunk: Data) throws { collected.append(chunk) }
    func finalize() throws { }
}

/// Convenience: gzip-compress `data` in one call. Drives the streaming
/// writer in-memory.
enum GzipOneShot {
    static func compress(_ data: Data) throws -> Data {
        let sink = DataCollector()
        let writer = try GzipStreamWriter(downstream: sink)
        try writer.consume(data)
        try writer.finalize()
        return sink.collected
    }
}

/// One-shot gzip decompressor used by the eager reader, the lazy reader,
/// the legacy 3.x reader, and the legacy inline-binary decompressor.
/// Initialized with `wBits = 47` (15 + 32) so zlib autodetects gzip or
/// zlib wrappers — KDBX uses gzip but the autodetect costs nothing.
///
/// `maxOutputBytes` caps the decompressed size and throws
/// `.outputTooLarge(limit:)` mid-stream once the cumulative output would
/// exceed it. The cap is enforced before any allocation past the limit,
/// so a payload that would inflate without bound fails fast rather than
/// after a runaway allocation.
enum GzipStreamReader {
    static func decompress(
        _ data: Data,
        maxOutputBytes: Int
    ) throws -> Data {
        var stream = z_stream()
        let initStatus = inflateInit2_(
            &stream,
            47, // wBits: 15 + 32 → autodetect gzip / zlib
            ZLIB_VERSION,
            Int32(MemoryLayout<z_stream>.size)
        )
        guard initStatus == Z_OK else {
            throw ZlibError.inflateInit(initStatus)
        }
        defer { inflateEnd(&stream) }

        let bufferSize = 64 * 1024
        var outputBuffer = [UInt8](repeating: 0, count: bufferSize)
        var result = Data()

        try data.withUnsafeBytes { (inputPtr: UnsafeRawBufferPointer) in
            let inputBase = inputPtr.bindMemory(to: UInt8.self).baseAddress
            stream.next_in = UnsafeMutablePointer<UInt8>(mutating: inputBase)
            stream.avail_in = UInt32(data.count)

            while true {
                let (status, produced): (Int32, Int) = try outputBuffer.withUnsafeMutableBufferPointer { outBuf in
                    stream.next_out = outBuf.baseAddress
                    stream.avail_out = UInt32(bufferSize)

                    let s = inflate(&stream, Z_NO_FLUSH)
                    // Z_BUF_ERROR is "make more progress" and the loop
                    // condition handles it; only abort on hard errors.
                    if s < 0, s != Z_BUF_ERROR {
                        throw ZlibError.inflate(s)
                    }
                    return (s, bufferSize - Int(stream.avail_out))
                }

                if produced > 0 {
                    if result.count + produced > maxOutputBytes {
                        throw ZlibError.outputTooLarge(limit: maxOutputBytes)
                    }
                    outputBuffer.withUnsafeBufferPointer { outBuf in
                        result.append(outBuf.baseAddress!, count: produced)
                    }
                }

                if status == Z_STREAM_END {
                    return
                }
                if stream.avail_in == 0, produced == 0 {
                    // No input left, no output produced — stream is truncated.
                    throw ZlibError.truncatedInput
                }
            }
        }

        return result
    }
}
