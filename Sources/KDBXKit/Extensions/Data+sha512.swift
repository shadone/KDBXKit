//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

extension Data {
    func sha512() -> Data {
        var sha512 = SHA512()
        sha512.update(data: self)
        return Data(sha512.finalize())
    }
}
