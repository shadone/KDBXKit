//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

extension Data {
    func hmacSha256(key: Data) -> Data {
        var hmac = HMAC<SHA256>(key: SymmetricKey(data: key))
        hmac.update(data: self)
        return Data(hmac.finalize())
    }
}
