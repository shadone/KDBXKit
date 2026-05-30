//
//  CryptoSwift
//
//  Copyright (C) 2014-2025 Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  Copyright (C) 2025 Denis Dzyubenko <denis@ddenis.info>
//
//  SPDX-License-Identifier: Zlib
//
//  This software is provided 'as-is', without any express or implied warranty.
//
//  In no event will the authors be held liable for any damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
//
//  - The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
//  - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
//  - This notice may not be removed or altered from any source or binary distribution.
//

//  https://tools.ietf.org/html/rfc7539
//

import Foundation

extension UInt32 {
    init(bytes: some DataProtocol) {
        self = UInt32(bytes: bytes, fromIndex: bytes.startIndex)
    }

    @inlinable
    init<T: DataProtocol>(bytes: T, fromIndex index: T.Index) {
        if bytes.isEmpty {
            self = 0
            return
        }

        let count = bytes.count

        let val0 = count > 0 ? UInt32(bytes[bytes.index(index, offsetBy: 0)]) << 24 : 0
        let val1 = count > 1 ? UInt32(bytes[bytes.index(index, offsetBy: 1)]) << 16 : 0
        let val2 = count > 2 ? UInt32(bytes[bytes.index(index, offsetBy: 2)]) << 8 : 0
        let val3 = count > 3 ? UInt32(bytes[bytes.index(index, offsetBy: 3)]) : 0

        self = val0 | val1 | val2 | val3
    }
}

public final class ChaCha20: Encryptable, Decryptable {
    public static let blockSize = 64 // 512 bits
    // Key and nonce parsed once into little-endian 32-bit words (RFC 7539
    // state words 4..11 and 13..15). The original CryptoSwift-derived code
    // re-parsed these from `any DataProtocol` on every 64-byte block, which
    // was a large part of why it ran at ~33 MB/s.
    private let keyWords: [UInt32] // 8 words
    private let nonceWords: [UInt32] // 3 words
    private var blockCounter: UInt32
    private var offsetInBlock: Int = 0
    // Keystream for the current `blockCounter`; regenerated when a block is
    // fully consumed (offsetInBlock wraps to 0), so a partial block carried
    // across `process` calls is not recomputed.
    private var keystream = [UInt8](repeating: 0, count: ChaCha20.blockSize)

    public init(key: any DataProtocol, iv nonce: any DataProtocol, blockCounter: UInt32 = 0) throws {
        guard key.count == 32 else {
            throw NSError(domain: "ChaCha20", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid key length"])
        }
        guard nonce.count == 12 else {
            throw NSError(domain: "ChaCha20", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid nonce length"])
        }

        // Little-endian word load, identical to the original core's
        // `UInt32(bytes:).bigEndian` (big-endian load, then byte-swap → LE).
        let keyBytes = Array(key)
        let nonceBytes = Array(nonce)
        keyWords = (0..<8).map { UInt32(bytes: keyBytes[($0 * 4)..<($0 * 4 + 4)]).bigEndian }
        nonceWords = (0..<3).map { UInt32(bytes: nonceBytes[($0 * 4)..<($0 * 4 + 4)]).bigEndian }
        self.blockCounter = blockCounter
    }

    public func encrypt(_ input: any DataProtocol) -> any DataProtocol {
        process(input: input)
    }

    public func decrypt(_ input: any DataProtocol) -> any DataProtocol {
        process(input: input)
    }

    private func process(input: any DataProtocol) -> any DataProtocol {
        let inBytes = [UInt8](input)
        let total = inBytes.count
        if total == 0 { return [UInt8]() }

        var output = [UInt8](repeating: 0, count: total)
        var processed = 0
        while processed < total {
            // (Re)generate the keystream for the current counter only at a
            // block boundary; a partially-consumed block carried over from a
            // previous call stays cached in `keystream`.
            if offsetInBlock == 0 {
                fillKeystream(counter: blockCounter)
            }

            let available = Self.blockSize - offsetInBlock
            let n = min(available, total - processed)
            let offset = offsetInBlock
            inBytes.withUnsafeBufferPointer { src in
                output.withUnsafeMutableBufferPointer { dst in
                    keystream.withUnsafeBufferPointer { ks in
                        for i in 0..<n {
                            dst[processed + i] = src[processed + i] ^ ks[offset + i]
                        }
                    }
                }
            }

            processed += n
            offsetInBlock += n
            if offsetInBlock == Self.blockSize {
                blockCounter += 1
                offsetInBlock = 0
            }
        }

        return output
    }

    /// https://tools.ietf.org/html/rfc7539#section-2.3.
    /// Runs the 20-round ChaCha core for `counter` and writes the 64-byte
    /// keystream into `self.keystream`. State words 4..11 are the key,
    /// word 12 the block counter, words 13..15 the nonce — the key/nonce
    /// words are parsed once in `init`, not per block.
    private func fillKeystream(counter: UInt32) {
        let j0: UInt32 = 0x61707865
        let j1: UInt32 = 0x3320646E // 0x3620646e sigma/tau
        let j2: UInt32 = 0x79622D32
        let j3: UInt32 = 0x6B206574

        let j4 = keyWords[0]
        let j5 = keyWords[1]
        let j6 = keyWords[2]
        let j7 = keyWords[3]
        let j8 = keyWords[4]
        let j9 = keyWords[5]
        let j10 = keyWords[6]
        let j11 = keyWords[7]
        let j12 = counter
        let j13 = nonceWords[0]
        let j14 = nonceWords[1]
        let j15 = nonceWords[2]

        var (x0, x1, x2, x3, x4, x5, x6, x7) = (j0, j1, j2, j3, j4, j5, j6, j7)
        var (x8, x9, x10, x11, x12, x13, x14, x15) = (j8, j9, j10, j11, j12, j13, j14, j15)

        for _ in 0..<10 { // 20 rounds
            x0 = x0 &+ x4
            x12 ^= x0
            x12 = (x12 << 16) | (x12 >> 16)
            x8 = x8 &+ x12
            x4 ^= x8
            x4 = (x4 << 12) | (x4 >> 20)
            x0 = x0 &+ x4
            x12 ^= x0
            x12 = (x12 << 8) | (x12 >> 24)
            x8 = x8 &+ x12
            x4 ^= x8
            x4 = (x4 << 7) | (x4 >> 25)
            x1 = x1 &+ x5
            x13 ^= x1
            x13 = (x13 << 16) | (x13 >> 16)
            x9 = x9 &+ x13
            x5 ^= x9
            x5 = (x5 << 12) | (x5 >> 20)
            x1 = x1 &+ x5
            x13 ^= x1
            x13 = (x13 << 8) | (x13 >> 24)
            x9 = x9 &+ x13
            x5 ^= x9
            x5 = (x5 << 7) | (x5 >> 25)
            x2 = x2 &+ x6
            x14 ^= x2
            x14 = (x14 << 16) | (x14 >> 16)
            x10 = x10 &+ x14
            x6 ^= x10
            x6 = (x6 << 12) | (x6 >> 20)
            x2 = x2 &+ x6
            x14 ^= x2
            x14 = (x14 << 8) | (x14 >> 24)
            x10 = x10 &+ x14
            x6 ^= x10
            x6 = (x6 << 7) | (x6 >> 25)
            x3 = x3 &+ x7
            x15 ^= x3
            x15 = (x15 << 16) | (x15 >> 16)
            x11 = x11 &+ x15
            x7 ^= x11
            x7 = (x7 << 12) | (x7 >> 20)
            x3 = x3 &+ x7
            x15 ^= x3
            x15 = (x15 << 8) | (x15 >> 24)
            x11 = x11 &+ x15
            x7 ^= x11
            x7 = (x7 << 7) | (x7 >> 25)
            x0 = x0 &+ x5
            x15 ^= x0
            x15 = (x15 << 16) | (x15 >> 16)
            x10 = x10 &+ x15
            x5 ^= x10
            x5 = (x5 << 12) | (x5 >> 20)
            x0 = x0 &+ x5
            x15 ^= x0
            x15 = (x15 << 8) | (x15 >> 24)
            x10 = x10 &+ x15
            x5 ^= x10
            x5 = (x5 << 7) | (x5 >> 25)
            x1 = x1 &+ x6
            x12 ^= x1
            x12 = (x12 << 16) | (x12 >> 16)
            x11 = x11 &+ x12
            x6 ^= x11
            x6 = (x6 << 12) | (x6 >> 20)
            x1 = x1 &+ x6
            x12 ^= x1
            x12 = (x12 << 8) | (x12 >> 24)
            x11 = x11 &+ x12
            x6 ^= x11
            x6 = (x6 << 7) | (x6 >> 25)
            x2 = x2 &+ x7
            x13 ^= x2
            x13 = (x13 << 16) | (x13 >> 16)
            x8 = x8 &+ x13
            x7 ^= x8
            x7 = (x7 << 12) | (x7 >> 20)
            x2 = x2 &+ x7
            x13 ^= x2
            x13 = (x13 << 8) | (x13 >> 24)
            x8 = x8 &+ x13
            x7 ^= x8
            x7 = (x7 << 7) | (x7 >> 25)
            x3 = x3 &+ x4
            x14 ^= x3
            x14 = (x14 << 16) | (x14 >> 16)
            x9 = x9 &+ x14
            x4 ^= x9
            x4 = (x4 << 12) | (x4 >> 20)
            x3 = x3 &+ x4
            x14 ^= x3
            x14 = (x14 << 8) | (x14 >> 24)
            x9 = x9 &+ x14
            x4 ^= x9
            x4 = (x4 << 7) | (x4 >> 25)
        }

        x0 = x0 &+ j0
        x1 = x1 &+ j1
        x2 = x2 &+ j2
        x3 = x3 &+ j3
        x4 = x4 &+ j4
        x5 = x5 &+ j5
        x6 = x6 &+ j6
        x7 = x7 &+ j7
        x8 = x8 &+ j8
        x9 = x9 &+ j9
        x10 = x10 &+ j10
        x11 = x11 &+ j11
        x12 = x12 &+ j12
        x13 = x13 &+ j13
        x14 = x14 &+ j14
        x15 = x15 &+ j15

        // Little-endian serialize each output word into `keystream`. This
        // matches the original `word.bigEndian.bytes()` (emit the byte-
        // swapped word big-endian == emit the word little-endian) on the
        // little-endian platforms KDBXKit targets.
        writeKeystreamWordLE(x0, at: 0)
        writeKeystreamWordLE(x1, at: 4)
        writeKeystreamWordLE(x2, at: 8)
        writeKeystreamWordLE(x3, at: 12)
        writeKeystreamWordLE(x4, at: 16)
        writeKeystreamWordLE(x5, at: 20)
        writeKeystreamWordLE(x6, at: 24)
        writeKeystreamWordLE(x7, at: 28)
        writeKeystreamWordLE(x8, at: 32)
        writeKeystreamWordLE(x9, at: 36)
        writeKeystreamWordLE(x10, at: 40)
        writeKeystreamWordLE(x11, at: 44)
        writeKeystreamWordLE(x12, at: 48)
        writeKeystreamWordLE(x13, at: 52)
        writeKeystreamWordLE(x14, at: 56)
        writeKeystreamWordLE(x15, at: 60)
    }

    private func writeKeystreamWordLE(_ word: UInt32, at offset: Int) {
        keystream[offset] = UInt8(truncatingIfNeeded: word)
        keystream[offset + 1] = UInt8(truncatingIfNeeded: word >> 8)
        keystream[offset + 2] = UInt8(truncatingIfNeeded: word >> 16)
        keystream[offset + 3] = UInt8(truncatingIfNeeded: word >> 24)
    }
}
