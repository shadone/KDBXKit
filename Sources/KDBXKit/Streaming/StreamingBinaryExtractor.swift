//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Terminal consumer that captures exactly ONE binary-pool payload (by
/// pool index) from the decompressed inner stream and streams it to a
/// sink, discarding every other byte.
///
/// The single-binary mirror of ``InnerHeaderXMLStreamConsumer``: it walks
/// the same inner-header TLV records, but where that consumer hashes every
/// binary and keeps the XML, this one forwards just the target binary's
/// bytes through `onChunk` and drops the rest. Peak memory is therefore the
/// sink's choice (a ``SecureBytesSink`` page, a ``URLSink`` file write),
/// never the whole payload — the property the lazy re-stream wants.
///
/// Sets ``done`` once the target binary has fully streamed. The block
/// driver polls it (`stopEarly:`) and stops as soon as it flips, so later
/// binaries and the trailing XML are never decrypted or inflated.
final class StreamingBinaryExtractor: StreamingByteConsumer {
    // Inner-header field type bytes (mirror InnerHeaderFieldType).
    private static let endOfHeader: UInt8 = 0
    private static let binaryContent: UInt8 = 3

    private let targetIndex: Int
    private let onChunk: (UnsafeRawBufferPointer) throws -> Void

    /// Work buffer for record framing. Holds at most one upstream chunk;
    /// binary payloads stream straight through, never accumulating.
    private var pending: [UInt8] = []
    private var sawEndOfHeader = false

    // Binary-record cursor.
    private var currentBinaryIndex = -1
    private var binaryRemaining = 0
    private var capturing = false

    /// True once the target binary has fully streamed to the sink.
    private(set) var done = false
    /// True once the target binary's record has been seen at all (even if
    /// zero-length). Stays false for an out-of-range index.
    private(set) var found = false

    init(targetIndex: Int, onChunk: @escaping (UnsafeRawBufferPointer) throws -> Void) {
        self.targetIndex = targetIndex
        self.onChunk = onChunk
    }

    func consume(_ chunk: Data) throws {
        guard !chunk.isEmpty, !done, !sawEndOfHeader else { return }
        pending.append(contentsOf: chunk)
        try parse()
    }

    func finalize() throws {
        // Nothing buffered to flush — the sink is finalized by the caller,
        // which owns its lifetime. But a stream that ends while the target
        // is still draining must fail loudly: finalizing here would hand
        // the caller a silently truncated attachment.
        if capturing, binaryRemaining > 0 {
            throw KDBXReader.Error.corruptedInnerHeader(
                reason: "Stream ended mid-binary: \(binaryRemaining) bytes of binary \(targetIndex) missing"
            )
        }
    }

    private func parse() throws {
        while !done {
            // Drain an in-progress binary payload first, never buffering it.
            if binaryRemaining > 0 {
                let take = min(binaryRemaining, pending.count)
                if take > 0 {
                    if capturing {
                        try pending.withUnsafeBytes {
                            try onChunk(UnsafeRawBufferPointer(rebasing: $0[0..<take]))
                        }
                    }
                    pending.removeFirst(take)
                    binaryRemaining -= take
                }
                if binaryRemaining > 0 { return } // need more chunks
                if capturing {
                    done = true // target fully captured
                    return
                }
                continue
            }

            guard pending.count >= 5 else { return } // need type(1) + length(4)
            let type = pending[0]
            let length = Int(
                UInt32(pending[1])
                    | UInt32(pending[2]) << 8
                    | UInt32(pending[3]) << 16
                    | UInt32(pending[4]) << 24
            )

            if type == Self.binaryContent {
                // value = flags(1) ‖ payload; a zero-length value has no
                // flags byte, and consuming one anyway would desync every
                // later record by a byte (mirrors InnerHeaderXMLStreamConsumer).
                guard length >= 1 else {
                    throw KDBXReader.Error.corruptedInnerHeader(reason: "Empty inner-header binaryContent field")
                }
                guard pending.count >= 6 else { return } // need the flags byte too
                pending.removeFirst(6) // type + length + flags
                currentBinaryIndex += 1
                binaryRemaining = length - 1 // value = flags(1) + payload
                capturing = currentBinaryIndex == targetIndex
                if capturing { found = true }
                if binaryRemaining == 0, capturing {
                    done = true // empty target captured immediately
                    return
                }
                continue
            }

            if type == Self.endOfHeader {
                // All binaries precede end-of-header; if we reach it without
                // having found the target the index was out of range (the
                // caller pre-validates against captured metadata, so this is
                // defensive). Stop — the rest is XML we don't need.
                sawEndOfHeader = true
                return
            }

            // Other small field (cipher algorithm / key) — skip its value.
            guard length <= InnerHeaderXMLStreamConsumer.maxSmallFieldLength else {
                throw KDBXReader.Error.corruptedInnerHeader(
                    reason: "Inner-header field of type \(type) declares an implausible length \(length)"
                )
            }
            let total = 5 + length
            guard pending.count >= total else { return }
            pending.removeFirst(total)
        }
    }
}
