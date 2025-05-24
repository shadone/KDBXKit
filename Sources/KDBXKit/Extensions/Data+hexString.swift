//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension Data {
    var hexString: String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}
