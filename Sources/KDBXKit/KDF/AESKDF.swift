//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#endif

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

        var block = [UInt8](buffer)
        defer {
            for index in block.indices { block[index] = 0 }
        }

        // Fast path: one AES key schedule, reused for every round. See
        // `transformReusingKeySchedule` for why this matters so much.
        if !transformReusingKeySchedule(&block, salt: salt, rounds: rounds) {
            // Portable fallback — identical algorithm, one key schedule per
            // block per round. Correct everywhere, just far slower.
            let key = SymmetricKey(data: salt)
            var left = Array(block[0 ..< 16])
            var right = Array(block[16 ..< 32])

            for _ in 0..<rounds {
                // AES.permute is single-block ECB; invariants above guarantee
                // success — failure here would be a swift-crypto bug.
                try! AES.permute(&left, key: key)
                try! AES.permute(&right, key: key)
            }

            block = left + right
        }

        var combined = Data(block)
        defer {
            combined.withUnsafeMutableBytes { ptr in
                _ = ptr.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        return SecureBytes(combined.sha256())
    }

    #if canImport(CommonCrypto)
    /// Run the AES-KDF inner loop with a single, reused AES key schedule.
    ///
    /// `AES.permute(_:key:)` takes a `SymmetricKey` per call, and internally
    /// calls `AES_set_encrypt_key` every time — so the key schedule is rebuilt
    /// once per block per round. A database with 47.6M rounds therefore
    /// expands the schedule ~95M times, and the expansion dominates the actual
    /// encryption. Hoisting it out is worth ~5x.
    ///
    /// ECB encrypts each 16-byte block independently, so a single 32-byte
    /// update covers both halves in one call and is exactly equivalent to
    /// permuting them separately.
    ///
    /// Returns `false` if CommonCrypto refuses at any point, so the caller can
    /// fall back to the portable path rather than produce a wrong key.
    private static func transformReusingKeySchedule(
        _ block: inout [UInt8],
        salt: Data,
        rounds: UInt64
    ) -> Bool {
        var cryptor: CCCryptorRef?
        let created = salt.withUnsafeBytes { saltBytes in
            CCCryptorCreate(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                saltBytes.baseAddress,
                saltBytes.count,
                nil,
                &cryptor
            )
        }
        guard created == kCCSuccess, let cryptor else { return false }
        defer { CCCryptorRelease(cryptor) }

        // Ping-pong buffer. Holds key material, so it is zeroed on the way out.
        var scratch = [UInt8](repeating: 0, count: 32)
        defer {
            for index in scratch.indices { scratch[index] = 0 }
        }

        var moved = 0
        for _ in 0..<rounds {
            let status = CCCryptorUpdate(cryptor, &block, 32, &scratch, 32, &moved)
            guard status == kCCSuccess, moved == 32 else { return false }
            swap(&block, &scratch)
        }
        return true
    }
    #else
    private static func transformReusingKeySchedule(
        _: inout [UInt8],
        salt _: Data,
        rounds _: UInt64
    ) -> Bool {
        false
    }
    #endif
}
