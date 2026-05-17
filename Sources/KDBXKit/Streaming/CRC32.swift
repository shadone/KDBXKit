//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Incremental CRC-32 (IEEE 802.3 polynomial 0xEDB88320), used by
/// the gzip footer. Standard 256-entry table.
internal struct CRC32 {
    private static let table: [UInt32] = {
        var table = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1
            }
            table[i] = c
        }
        return table
    }()

    private(set) var value: UInt32 = 0xFFFFFFFF

    mutating func update(_ data: Data) {
        var crc = value
        data.withUnsafeBytes { buf in
            let bytes = buf.bindMemory(to: UInt8.self)
            for byte in bytes {
                crc = Self.table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
            }
        }
        value = crc
    }

    /// Final CRC32 value (xor-with-0xFFFFFFFF on the rolling value).
    var finalized: UInt32 {
        value ^ 0xFFFFFFFF
    }
}
