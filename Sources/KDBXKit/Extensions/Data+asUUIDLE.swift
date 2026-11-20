//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Data {
    /// The 16 bytes as a UUID in RFC 4122 order, as XML `<UUID>` values
    /// store them.
    func asUUID() -> UUID? {
        if count != 16 {
            return nil
        }
        return UUID(uuid: (
            self[startIndex + 0], self[startIndex + 1], self[startIndex + 2], self[startIndex + 3],
            self[startIndex + 4], self[startIndex + 5], self[startIndex + 6], self[startIndex + 7],
            self[startIndex + 8], self[startIndex + 9], self[startIndex + 10], self[startIndex + 11],
            self[startIndex + 12], self[startIndex + 13], self[startIndex + 14], self[startIndex + 15]
        ))
    }

    /// The 16 bytes reversed; header fields such as the KDF `$UUID` are
    /// compared with constants in this order.
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
