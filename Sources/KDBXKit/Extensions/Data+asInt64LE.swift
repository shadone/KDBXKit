//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asInt64LE() -> Int64? {
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
            Int64(b8) << 56 | Int64(b7) << 48 | Int64(b6) << 40 | Int64(b5) << 32 |
            Int64(b4) << 24 | Int64(b3) << 16 | Int64(b2) << 8 | Int64(b1)

        return value
    }
}
