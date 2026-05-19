//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

extension Data {
    func sha256() -> Data {
        var sha256 = SHA256()
        sha256.update(data: self)
        return Data(sha256.finalize())
    }
}
