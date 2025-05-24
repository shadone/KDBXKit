//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asUInt64LE() -> UInt64? {
        if count != 8 {
            return nil
        }

        let b1 = self[startIndex]
        let b2 = self[startIndex + 1]
        let b3 = self[startIndex + 2]
        let b4 = self[startIndex + 3]
        let b5 = self[startIndex + 4]
        let b6 = self[startIndex + 5]
        let b7 = self[startIndex + 6]
        let b8 = self[startIndex + 7]

        // little endian
        let value =
            UInt64(b8) << 56 | UInt64(b7) << 48 | UInt64(b6) << 40 | UInt64(b5) << 32 |
            UInt64(b4) << 24 | UInt64(b3) << 16 | UInt64(b2) << 8 | UInt64(b1)

        return value
    }
}
