//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct UUIDUInt128ConversionTests {
    @Test
    func testUUIDToUInt128RoundTrip() {
        let originalUUID = UUID()
        let value = originalUUID.toUInt128()
        let reconstructed = UUID(uint128: value)
        #expect(reconstructed == originalUUID)
    }

    @Test
    func testKnownValueConversion() {
        let bytes: [UInt8] = [
            0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
        ]
        let uuid = UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
        let value = uuid.toUInt128()
        let reconstructed = UUID(uint128: value)
        #expect(reconstructed == uuid)
    }
}
