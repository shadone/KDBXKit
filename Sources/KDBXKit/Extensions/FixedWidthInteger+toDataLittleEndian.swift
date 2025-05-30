//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension FixedWidthInteger {
    /// Converts the integer to `Data` in little-endian byte order.
    func toDataLittleEndian() -> Data {
        var value = littleEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
