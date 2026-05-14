//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

enum HMACProtectedBlockStream {
    /// The HMAC key for the i-th block. Built from the SecureBytes-backed
    /// unlock key; returns plain `Data` because the HMAC key feeds straight
    /// into `CryptoKit.SymmetricKey` which takes a ContiguousBytes anyway,
    /// and the result is per-block + immediately consumed.
    static func keyForBlock(at index: UInt64, masterSalt: Data, unlockKey: SecureBytes) -> Data {
        // The key for the HMAC-SHA-256 hash of the i-th block (zero-based index, type UInt64)
        // of the HMAC-protected block stream is:
        // SHA-512(i ‖ SHA-512(S ‖ T ‖ 0x01)).
        unlockKey.withUnsafeBytes { ukPtr in
            // Build masterSalt ‖ unlockKey ‖ 0x01 in a transient buffer we zero
            // after use. SecureBytes is overkill here — per-call lifetime, no
            // copy escapes.
            var combined = masterSalt
            combined.append(contentsOf: ukPtr.bindMemory(to: UInt8.self))
            combined.append(0x01)
            defer {
                combined.withUnsafeMutableBytes { ptr in
                    ptr.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }
            return (index.dataLE + combined.sha512()).sha512()
        }
    }

    static func keyForHeader(masterSalt: Data, unlockKey: SecureBytes) -> Data {
        // The key for the HMAC-SHA-256 hash of the header is:
        // SHA-512(0xFFFFFFFFFFFFFFFF ‖ SHA-512(S ‖ T ‖ 0x01)).
        let lastIndex: UInt64 = 0xFFFFFFFFFFFFFFFF
        return keyForBlock(at: lastIndex, masterSalt: masterSalt, unlockKey: unlockKey)
    }
}
