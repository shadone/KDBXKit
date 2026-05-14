//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Constant-time helpers for comparing secret-derived byte sequences.
///
/// `Data == Data` short-circuits on the first mismatched byte. For HMAC
/// authentication tags that means an attacker who can measure the time
/// it takes to reject a guess learns roughly how many leading bytes of
/// their guess matched. KDBX is offline so timing channels aren't free
/// to attackers, but using `==` on authentication tags is straightforwardly
/// the wrong tool — this is.
enum ConstantTime {
    /// Returns `true` iff `lhs` and `rhs` contain the same bytes in the
    /// same order. Inspects every byte regardless of where the mismatch is.
    /// Returns `false` immediately for different-length inputs (the length
    /// itself is not secret here — HMACs are fixed-width).
    static func equals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return lhs.withUnsafeBytes { (l: UnsafeRawBufferPointer) -> Bool in
            rhs.withUnsafeBytes { (r: UnsafeRawBufferPointer) -> Bool in
                var diff: UInt8 = 0
                for i in 0..<l.count {
                    diff |= l[i] ^ r[i]
                }
                return diff == 0
            }
        }
    }
}
