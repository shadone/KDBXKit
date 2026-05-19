//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

enum SecureRandom {
    /// Returns `length` bytes from the system CSPRNG.
    ///
    /// Backed by Swift's `SystemRandomNumberGenerator`, which on Apple
    /// platforms wraps `arc4random_buf` (ultimately `getentropy`) and on
    /// Linux wraps `getrandom(2)`. Both are cryptographically secure and
    /// can't be exhausted under normal kernel operation, so failure here
    /// would indicate a fundamentally broken system; we crash rather
    /// than return predictable bytes.
    static func bytes(_ length: Int) -> Data {
        precondition(length >= 0, "Length must be non-negative")
        var bytes = [UInt8](repeating: 0, count: length)
        var rng = SystemRandomNumberGenerator()
        var i = 0
        while i < length {
            let chunk = rng.next()
            withUnsafeBytes(of: chunk) { src in
                let take = Swift.min(MemoryLayout<UInt64>.size, length - i)
                for j in 0..<take {
                    bytes[i + j] = src[j]
                }
                i += take
            }
        }
        return Data(bytes)
    }
}
