//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asUInt32LE() -> UInt32? {
        if count != 4 {
            return nil
        }

        let b1 = self[startIndex]
        let b2 = self[startIndex + 1]
        let b3 = self[startIndex + 2]
        let b4 = self[startIndex + 3]

        // little endian
        let value = UInt32(b4) << 24 | UInt32(b3) << 16 | UInt32(b2) << 8 | UInt32(b1)
        return value
    }
}
