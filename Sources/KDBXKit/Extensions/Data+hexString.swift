//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension Data {
    /// Creates a `Data` instance from a hexadecimal string.
    ///
    /// The input string must consist of an even number of valid hexadecimal characters
    /// (0-9, a-f, A-F). Whitespace and prefixes like `0x` are not allowed.
    ///
    /// For example, the string `"deadbeef"` creates a `Data` instance
    /// with bytes `[0xde, 0xad, 0xbe, 0xef]`.
    ///
    /// - Parameter hexString: The hexadecimal string to parse.
    /// - Returns: A `Data` instance if parsing succeeds; otherwise, `nil`.
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        let numberOfBytes = hexString.count / 2

        var data = Data(capacity: numberOfBytes)
        var index = hexString.startIndex

        for _ in 0..<numberOfBytes {
            let nextIndex = hexString.index(index, offsetBy: 2)
            let byteString = hexString[index..<nextIndex]
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
            index = nextIndex
        }

        self = data
    }

    /// A lowercase hexadecimal string representation of the data.
    ///
    /// Each byte in the data is represented by two hex digits. For example,
    /// a byte with value `0xAF` will appear as `"af"` in the resulting string.
    ///
    /// - Returns: A string containing the hexadecimal representation of the data.
    var hexString: String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}
