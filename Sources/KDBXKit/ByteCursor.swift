//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// A forward-only, bounds-checked reader over a `Data` buffer.
///
/// The KDBX binary parsers (`HeaderReader`, `Header3xReader`,
/// `InnerHeaderReader`, `VariantDictionaryReader`) each used to re-implement
/// the same `pos` / `readUInt8` / `readData(length:)` primitives with the
/// same two easy-to-miss guards: rejecting a negative length before it builds
/// a reversed `start..<end` range and traps, and comparing against
/// `endIndex` (not `count`) so the bounds check stays correct for a
/// non-zero-based slice. Centralizing them here means a fix lands once, not
/// once per reader.
///
/// `position` is an absolute `Data.Index` into the original buffer (it starts
/// at `data.startIndex`, not 0), so a cursor handed a `Data` slice reads the
/// right bytes without the caller re-basing it first.
struct ByteCursor: Sendable {
    enum Error: Swift.Error, Equatable {
        /// A read ran past the end of the buffer, or a negative length was
        /// requested (a signed wire field with its high bit set).
        case unexpectedEOF
    }

    private let data: Data

    /// The absolute index of the next byte to read.
    private(set) var position: Data.Index

    init(_ data: Data) {
        self.data = data
        position = data.startIndex
    }

    /// Whether the cursor has consumed every byte.
    var isAtEnd: Bool { position >= data.endIndex }

    /// Skip `n` bytes without reading them. Used to step over a sub-region
    /// already consumed by a nested reader (e.g. past a parsed header). `n`
    /// must be non-negative; advancing beyond the end is allowed and simply
    /// leaves later reads to throw `unexpectedEOF`.
    mutating func advance(by n: Int) {
        precondition(n >= 0, "ByteCursor.advance(by:) requires a non-negative count")
        position = position.advanced(by: n)
    }

    /// Move to a previously captured absolute position in the same buffer.
    /// Used by the lazy re-stream path, which records the index where the
    /// block stream begins and resumes a fresh cursor there to avoid
    /// re-deriving it. Not bounds-checked — a later read past the end still
    /// throws `unexpectedEOF`.
    mutating func seek(to index: Data.Index) {
        position = index
    }

    mutating func readUInt8() throws(Error) -> UInt8 {
        if position.advanced(by: 1) > data.endIndex {
            throw .unexpectedEOF
        }
        let b = data[position]
        position = position.advanced(by: 1)
        return b
    }

    mutating func readUInt16LE() throws(Error) -> UInt16 {
        // Safe to force-unwrap: readData guaranteed exactly 2 bytes.
        try readData(length: 2).asUInt16LE()!
    }

    mutating func readUInt32LE() throws(Error) -> UInt32 {
        try readData(length: 4).asUInt32LE()!
    }

    mutating func readInt32LE() throws(Error) -> Int32 {
        try readData(length: 4).asInt32LE()!
    }

    mutating func readData(length: Int) throws(Error) -> Data {
        // Reject a negative length (a signed wire field with the high bit set)
        // before it builds a reversed `start..<end` Range and traps.
        if length < 0 {
            throw .unexpectedEOF
        }
        let start = position
        let end = position.advanced(by: length)
        if end > data.endIndex {
            throw .unexpectedEOF
        }
        let subdata = data.subdata(in: start..<end)
        position = end
        return subdata
    }
}
