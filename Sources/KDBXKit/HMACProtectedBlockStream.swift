//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

enum HMACProtectedBlockStream {
    static func keyForBlock(at index: UInt64, masterSalt: Data, unlockKey: Data) -> Data {
        // The key for the HMAC-SHA-256 hash of the i-th block (zero-based index, type UInt64)
        // of the HMAC-protected block stream is:
        // SHA-512(i ‖ SHA-512(S ‖ T ‖ 0x01)).
        (index.dataLE + (masterSalt + unlockKey + Data([0x01])).sha512()).sha512()
    }

    static func keyForHeader(masterSalt: Data, unlockKey: Data) -> Data {
        // The key for the HMAC-SHA-256 hash of the header is:
        // SHA-512(0xFFFFFFFFFFFFFFFF ‖ SHA-512(S ‖ T ‖ 0x01)).
        let lastIndex: UInt64 = 0xFFFFFFFFFFFFFFFF
        return keyForBlock(at: lastIndex, masterSalt: masterSalt, unlockKey: unlockKey)
    }
}
