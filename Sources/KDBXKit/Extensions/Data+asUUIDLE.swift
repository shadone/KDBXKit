//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    func asUUIDLE() -> UUID? {
        if count != 16 {
            return nil
        }
        return UUID(uuid: (
            self[startIndex + 15], self[startIndex + 14], self[startIndex + 13], self[startIndex + 12],
            self[startIndex + 11], self[startIndex + 10], self[startIndex + 9], self[startIndex + 8],
            self[startIndex + 7], self[startIndex + 6], self[startIndex + 5], self[startIndex + 4],
            self[startIndex + 3], self[startIndex + 2], self[startIndex + 1], self[startIndex + 0]
        ))
    }
}
