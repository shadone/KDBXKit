//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// `OutputStream` subclass that accumulates writes into an in-memory `Data`
/// buffer with a hard maximum-size cap. Returns `-1` from `write` once the
/// cap would be exceeded so callers that honor the standard `OutputStream`
/// failure contract (e.g. swift-gzip's stream-based decompressor) abort the
/// operation immediately instead of allowing an unbounded allocation.
///
/// Used by `KDBXReader` to bound gzip decompression against payloads that
/// would otherwise inflate without limit (a "zip bomb" against the decrypted
/// payload — only reachable post-HMAC-verify, so really a robustness rather
/// than active-attack defense).
final class CappedDataOutputStream: OutputStream, @unchecked Sendable {
    private let cap: Int
    private var buffer = Data()

    /// `true` once a `write` call exceeded the cap and was rejected. Use to
    /// distinguish a real downstream failure from a cap-hit when the gzip
    /// decompressor throws.
    private(set) var overflowed = false

    init(cap: Int) {
        self.cap = cap
        super.init(toMemory: ())
    }

    /// The bytes accumulated so far. Safe to call after the stream has been
    /// fully consumed; the result is only meaningful if `overflowed == false`.
    var collected: Data { buffer }

    override var streamStatus: Stream.Status { .open }
    override var streamError: Swift.Error? { nil }
    override func open() {}
    override func close() {}
    override var hasSpaceAvailable: Bool { buffer.count < cap }

    override func write(_ writeBuffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
        if buffer.count &+ len > cap {
            overflowed = true
            return -1
        }
        buffer.append(writeBuffer, count: len)
        return len
    }
}
