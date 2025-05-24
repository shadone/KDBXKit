//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension UInt64 {
    var dataLE: Data {
        var valueInLittleEndian = littleEndian
        return withUnsafeBytes(of: &valueInLittleEndian) { Data($0) }
    }
}
