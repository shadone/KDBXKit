//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

enum MainKey {
    /// Returns the key used for encrypting/decrypting the main payload - the XML document.
    ///
    /// Overview of a KDBX file:
    ///
    /// ```
    ///                                      This class:
    /// 1. Header.
    /// 2. SHA-256 hash of the header.
    /// 3. HMAC-SHA-256 hash of the header.
    /// 4. In HMAC-protected block stream:
    ///    a. Encrypted:                     <<- key for this
    ///       i. Compressed (optional):
    ///          - Inner header.
    ///          - XML document.
    /// ```
    static func make(masterSalt: Data, unlockKey: SecureBytes) -> SecureBytes {
        // If the encryption algorithm needs a 256-bit key (such as AES-256 and ChaCha20),
        // the key is:
        // SHA-256(S ‖ T).
        // If the encryption algorithm needs a key smaller than 256 bits, the key consists of
        // the first bytes of SHA-256(S ‖ T).
        unlockKey.withUnsafeBytes { ukPtr in
            var combined = masterSalt
            combined.append(contentsOf: ukPtr.bindMemory(to: UInt8.self))
            defer {
                combined.withUnsafeMutableBytes { ptr in
                    ptr.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }
            return SecureBytes(combined.sha256())
        }
    }
}
