//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asInt32LE() -> Int32? {
        if count != 4 {
            return nil
        }

        let b1 = self[startIndex]
        let b2 = self[startIndex + 1]
        let b3 = self[startIndex + 2]
        let b4 = self[startIndex + 3]

        // little endian
        let value = Int32(b4) << 24 | Int32(b3) << 16 | Int32(b2) << 8 | Int32(b1)
        return value
    }
}
