//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("ConstantTime — functional correctness")
struct ConstantTimeTests {
    @Test
    func equalEqualBytes() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        #expect(ConstantTime.equals(a, b))
    }

    @Test
    func differentLastByte() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x05])
        #expect(!ConstantTime.equals(a, b))
    }

    @Test
    func differentFirstByte() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0xFF, 0x02, 0x03, 0x04])
        #expect(!ConstantTime.equals(a, b))
    }

    @Test
    func differentLength() {
        let a = Data([0x01, 0x02, 0x03])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        #expect(!ConstantTime.equals(a, b))
    }

    @Test
    func bothEmpty() {
        #expect(ConstantTime.equals(Data(), Data()))
    }
}
