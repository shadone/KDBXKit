//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Random-access façade over the KDBX inner stream cipher. Holds the
/// inner key + algorithm constants so any caller (lazy `ProtectedString`
/// values, in particular) can decrypt a specific slice of the inner
/// keystream without keeping a stateful cipher instance alive.
///
/// The KDBX inner cipher is a stream cipher (ChaCha20 in modern files,
/// Salsa20 in legacy ones). Both produce a deterministic keystream
/// indexed by a block counter — `KeystreamSource.decrypt(ciphertext:at:)`
/// recomputes the relevant block(s) on demand from `(key, nonce, offset)`
/// so an entry's protected bytes can stay encrypted in memory until the
/// moment they're read.
///
/// Value-typed and `Sendable` — the key lives in `SecureBytes` so the
/// underlying buffer is `mlock`'d and zeroed on deinit. Each `decrypt`
/// call constructs a fresh, ephemeral stateful cipher; that cipher
/// never crosses thread boundaries.
public struct KeystreamSource: Sendable {
    public enum Algorithm: Sendable, Equatable {
        case chacha20
        case salsa20
    }

    /// The inner-cipher algorithm tag from the file's inner header.
    public let algorithm: Algorithm

    /// The inner cipher key. For ChaCha20: 32 bytes derived from
    /// SHA-512(K)[0..32]. For Salsa20: 32 bytes derived from SHA-256(K).
    public let key: SecureBytes

    /// The cipher's fixed nonce / IV. 12 bytes for ChaCha20 (SHA-512(K)
    /// continued), 8 bytes for Salsa20 (the constant
    /// 0xE830094B97205D2A from the KDBX spec).
    public let nonce: Data

    public init(algorithm: Algorithm, key: SecureBytes, nonce: Data) {
        self.algorithm = algorithm
        self.key = key
        self.nonce = nonce
    }

    /// Decrypt `ciphertext`, treating it as a slice of the inner-cipher
    /// keystream starting at byte `offset`. Returns the plaintext bytes
    /// in fresh `SecureBytes` — the caller decides how long they live.
    ///
    /// `offset` must match the byte offset at which the corresponding
    /// ciphertext was originally produced by the inner cipher (i.e. the
    /// running offset the writer was at when it emitted these bytes).
    /// Mismatches will produce gibberish, not an error — stream ciphers
    /// have no MAC.
    public func decrypt(ciphertext: Data, at offset: Int) -> SecureBytes {
        precondition(offset >= 0, "offset must be non-negative")

        let blockSize = 64
        let blockCounter = offset / blockSize
        let bytesIntoBlock = offset % blockSize

        let cipher = makeCipher(blockCounter: UInt64(blockCounter))

        // The stateful cipher classes start at offsetInBlock = 0. To
        // start `bytesIntoBlock` bytes into the block, feed it that
        // many discard bytes first — the keystream advances, the
        // output is thrown away.
        if bytesIntoBlock > 0 {
            _ = cipher.decrypt(Data(repeating: 0, count: bytesIntoBlock))
        }

        let plain = cipher.decrypt(ciphertext)
        var plainBytes = Array(plain)
        defer {
            // Zero the transient plaintext copy before its heap storage is
            // released — SecureBytes copies the bytes into its arena.
            plainBytes.withUnsafeMutableBufferPointer { ptr in
                guard let base = ptr.baseAddress else { return }
                base.initialize(repeating: 0, count: ptr.count)
            }
        }
        return SecureBytes(plainBytes)
    }

    private func makeCipher(blockCounter: UInt64) -> any Decryptable {
        key.withUnsafeBytes { keyPtr -> any Decryptable in
            let keyData = Data(keyPtr.bindMemory(to: UInt8.self))
            // The cipher class copies the key into its own backing
            // store; we don't keep the transient Data around beyond
            // this constructor.
            switch algorithm {
            case .chacha20:
                // ChaCha20's blockCounter is UInt32 in the KDBX inner
                // cipher. KDBX won't realistically index past 4 GiB of
                // protected XML, but truncating is fine — a misuse
                // would just decrypt to garbage, same as offset
                // mismatch.
                return try! ChaCha20(key: keyData, iv: nonce, blockCounter: UInt32(truncatingIfNeeded: blockCounter))
            case .salsa20:
                return try! Salsa20(key: keyData, iv: nonce, blockCounter: blockCounter)
            }
        }
    }
}
