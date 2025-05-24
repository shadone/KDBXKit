//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asUInt16LE() -> UInt16? {
        if count != 2 {
            return nil
        }

        let b1 = self[startIndex]
        let b2 = self[startIndex + 1]

        // little endian
        let value = UInt16(b2) << 8 | UInt16(b1)
        return value
    }
}
