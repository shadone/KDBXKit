//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing

@testable import KDBXKit

struct IntegerDataConversionTests {
    @Test
    func int8RoundTrip() {
        let value: UInt8 = 123
        let data = value.toDataLittleEndian()
        #expect(data.count == 1)
        #expect(UInt8(littleEndianData: data) == value)
    }

    @Test
    func int32RoundTrip() {
        let value: Int32 = -123_456_789
        let data = value.toDataLittleEndian()
        #expect(data.count == 4)
        #expect(Int32(littleEndianData: data) == value)
    }

    @Test
    func uint32RoundTrip() {
        let value: UInt32 = 123_456_789
        let data = value.toDataLittleEndian()
        #expect(data.count == 4)
        #expect(UInt32(littleEndianData: data) == value)
    }

    @Test
    func int64RoundTrip() {
        let value: Int64 = -9_876_543_210_123_456
        let data = value.toDataLittleEndian()
        #expect(data.count == 8)
        #expect(Int64(littleEndianData: data) == value)
    }

    @Test
    func uint64RoundTrip() {
        let value: UInt64 = 9_876_543_210_123_456
        let data = value.toDataLittleEndian()
        #expect(data.count == 8)
        #expect(UInt64(littleEndianData: data) == value)
    }

    @Test
    func failOnWrongSize() {
        let data = Data([0x01, 0x02]) // Too short
        #expect(Int32(littleEndianData: data) == nil)
    }

    @Test
    func endianByteOrderCorrectness() {
        let value: UInt32 = 0x78563412
        let data = value.toDataLittleEndian()
        #expect(data == Data([0x12, 0x34, 0x56, 0x78]))
    }
}
