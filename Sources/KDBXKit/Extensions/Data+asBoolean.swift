//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asBoolean() -> Bool? {
        if count != 1 {
            return nil
        }

        let b1 = self[startIndex]
        return b1 != 0
    }
}
