//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

enum AESKDF {
    /// AES-KDF: iterate AES-256-ECB single-block encryption `rounds` times
    /// over each half of the 32-byte input, then SHA-256 the result.
    ///
    /// Returns `SecureBytes` so the derived key is held in zero-on-deinit
    /// storage from the moment it's produced.
    static func derive(salt: Data, rounds: UInt64, _ password: SecureBytes) -> SecureBytes {
        precondition(salt.count == 32, "AESKDF: Invalid salt size")
        precondition(password.count == 32, "AESKDF: Invalid key size \(password.count) != 32")

        // `buffer` is the running AES-encrypted state. It holds key material;
        // we use Data here for the in-loop arithmetic (slicing + concat) but
        // wrap the final result in SecureBytes. The transient Data is zeroed
        // before this function returns.
        var buffer = password.toData()
        defer {
            buffer.withUnsafeMutableBytes { ptr in
                _ = ptr.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        // KeePass AES-KDF: the 32-byte input is split into two 16-byte blocks
        // and each is independently encrypted with AES-256-ECB `rounds` times
        // using `salt` as the key. Final output is SHA-256 of the concatenated
        // ciphertexts.
        //
        // See: https://keepass.info/help/kb/kdbx_4.html and the
        // KeePassXC reference implementation (`Kdbx4Reader::transformKeyAes`).

        let key = SymmetricKey(data: salt)
        var left = Array(buffer.prefix(16))
        var right = Array(buffer.suffix(16))

        for _ in 0..<rounds {
            // AES.permute is single-block ECB; invariants above guarantee
            // success — failure here would be a swift-crypto bug.
            try! AES.permute(&left, key: key)
            try! AES.permute(&right, key: key)
        }

        var combined = Data(left)
        combined.append(contentsOf: right)
        defer {
            combined.withUnsafeMutableBytes { ptr in
                _ = ptr.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        return SecureBytes(combined.sha256())
    }
}
