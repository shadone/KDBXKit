//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension UUID {
    /// Initializes a `UUID` from raw 128-bit number. interpreting the raw bytes in **big-endian** order.
    init(uint128: UInt128) {
        var bytes = [UInt8]()
        withUnsafeBytes(of: uint128.bigEndian) { bytes.append(contentsOf: $0) }

        self = UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    /// Returns the UUID as a `UInt128`, interpreting the raw bytes in **big-endian** order,
    /// consistent with RFC 4122 and Swift’s `UUID` string representation.
    func toUInt128() -> UInt128 {
        // The load must happen inside the closure (the pointer is only
        // valid there), and the uuid tuple carries no 16-byte alignment
        // guarantee — load(as:) would be UB on both counts.
        withUnsafeBytes(of: uuid) { UInt128(bigEndian: $0.loadUnaligned(as: UInt128.self)) }
    }
}
