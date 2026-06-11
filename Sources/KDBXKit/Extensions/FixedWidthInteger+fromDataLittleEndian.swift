//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension FixedWidthInteger {
    /// Initializes an integer from a `Data` value interpreted in little-endian byte order.
    ///
    /// - Parameter data: A `Data` instance of exactly the expected size (e.g. 4 bytes for `Int32`).
    ///
    /// - Returns: An instance of the integer type if `data.count` matches the expected size, otherwise `nil`.
    init?(littleEndianData data: Data) {
        guard data.count == MemoryLayout<Self>.size else {
            return nil
        }

        // loadUnaligned: a Data slice gives no alignment guarantee for its
        // base address, and load(as:) traps on a misaligned pointer.
        self = data.withUnsafeBytes { ptr in
            ptr.loadUnaligned(as: Self.self)
        }.littleEndian
    }
}
