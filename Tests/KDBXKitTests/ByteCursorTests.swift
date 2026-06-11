//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// `ByteCursor` is the single bounds-checked reader the header-family parsers
/// share. The guard logic it centralizes (negative length, reading past
/// `endIndex`, non-zero-based slices) previously lived copy-pasted in six
/// readers; these tests pin the behavior every one of them relied on.
@Suite("ByteCursor")
struct ByteCursorTests {
    @Test("Sequential reads advance position and decode little-endian")
    func sequentialReads() throws {
        // u8=0x01, u16=0x0302, u32=0x07060504, i32=0x0B0A0908
        let bytes = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B])
        var cursor = ByteCursor(bytes)
        #expect(try cursor.readUInt8() == 0x01)
        #expect(try cursor.readUInt16LE() == 0x0302)
        #expect(try cursor.readUInt32LE() == 0x07060504)
        #expect(try cursor.readInt32LE() == 0x0B0A0908)
        #expect(cursor.position == bytes.endIndex)
    }

    @Test("readData returns the requested slice and advances")
    func readDataAdvances() throws {
        let bytes = Data([10, 20, 30, 40, 50])
        var cursor = ByteCursor(bytes)
        #expect(try cursor.readData(length: 2) == Data([10, 20]))
        #expect(try cursor.readData(length: 3) == Data([30, 40, 50]))
        #expect(cursor.position == bytes.endIndex)
    }

    @Test("readData(length: 0) is a no-op that returns empty")
    func zeroLengthRead() throws {
        var cursor = ByteCursor(Data([1, 2, 3]))
        let start = cursor.position
        #expect(try cursor.readData(length: 0).isEmpty)
        #expect(cursor.position == start)
    }

    @Test("Reading past the end throws unexpectedEOF, never traps")
    func readPastEnd() {
        var cursor = ByteCursor(Data([1, 2]))
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try cursor.readUInt32LE()
        }
        var cursor2 = ByteCursor(Data([1, 2]))
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try cursor2.readData(length: 3)
        }
        var empty = ByteCursor(Data())
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try empty.readUInt8()
        }
    }

    @Test("A negative length is rejected before it builds a reversed range")
    func negativeLength() {
        var cursor = ByteCursor(Data([1, 2, 3, 4]))
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try cursor.readData(length: -1)
        }
        // A negative Int32 length on the wire (high bit set) reaches readData
        // as a large-magnitude negative Int after the cast; still rejected.
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try cursor.readData(length: Int(Int32(bitPattern: 0xFFFFFFFF)))
        }
    }

    @Test("Position is absolute, so a non-zero-based slice reads correctly")
    func nonZeroBasedSlice() throws {
        // Drop the first 3 bytes to get a slice whose startIndex is 3.
        let slice = Data([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]).dropFirst(3)
        #expect(slice.startIndex == 3)
        var cursor = ByteCursor(Data(slice)) // re-based copy
        #expect(try cursor.readData(length: 3) == Data([0x11, 0x22, 0x33]))

        // And directly over the non-zero-based slice (no re-basing): the
        // cursor must honor startIndex, not assume 0.
        var rawCursor = ByteCursor(slice)
        #expect(try rawCursor.readUInt8() == 0x11)
        #expect(try rawCursor.readUInt8() == 0x22)
    }

    @Test("A partial read leaves position where the last successful read ended")
    func partialReadPosition() throws {
        var cursor = ByteCursor(Data([1, 2, 3, 4, 5]))
        _ = try cursor.readData(length: 4)
        let afterFour = cursor.position
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try cursor.readData(length: 4) // only 1 left
        }
        // Failed read does not advance.
        #expect(cursor.position == afterFour)
        #expect(try cursor.readUInt8() == 5)
    }

    @Test("advance(by:) skips bytes so the next read resumes past them")
    func advanceSkips() throws {
        var cursor = ByteCursor(Data([1, 2, 3, 4, 5]))
        cursor.advance(by: 3)
        #expect(cursor.position == cursor.position) // sanity: no trap
        #expect(try cursor.readUInt8() == 4)
        #expect(try cursor.readUInt8() == 5)
    }

    @Test("advance(by:) past the end leaves subsequent reads throwing, not trapping")
    func advancePastEnd() {
        var cursor = ByteCursor(Data([1, 2]))
        cursor.advance(by: 10)
        #expect(cursor.isAtEnd)
        #expect(throws: ByteCursor.Error.unexpectedEOF) {
            _ = try cursor.readUInt8()
        }
    }

    @Test("seek(to:) resumes reading at a previously captured absolute position")
    func seekResumes() throws {
        let bytes = Data([10, 20, 30, 40, 50])
        var cursor = ByteCursor(bytes)
        _ = try cursor.readData(length: 2)
        let mark = cursor.position // points at 30

        // A fresh cursor over the same buffer can be moved to the mark and
        // continue as if it had read the same prefix — the pattern the lazy
        // re-stream path uses to resume at the start of the block stream.
        var resumed = ByteCursor(bytes)
        resumed.seek(to: mark)
        #expect(resumed.position == mark)
        #expect(try resumed.readUInt8() == 30)
    }
}
