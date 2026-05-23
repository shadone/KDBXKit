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

import Foundation

public final class Salsa20: Encryptable & Decryptable {
    public static let blockSize = 64
    private let key: any DataProtocol
    private let nonce: any DataProtocol
    private var blockCounter: UInt64
    private var offsetInBlock: Int = 0

    public init(key: any DataProtocol, iv nonce: any DataProtocol, blockCounter: UInt64 = 0) throws {
        guard key.count == 32 else {
            throw NSError(domain: "Salsa20", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid key length"])
        }
        guard nonce.count == 8 else {
            throw NSError(domain: "Salsa20", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid nonce length"])
        }

        self.key = key
        self.nonce = nonce
        self.blockCounter = blockCounter
    }

    public func encrypt(_ input: any DataProtocol) -> any DataProtocol {
        process(input: input)
    }

    public func decrypt(_ input: any DataProtocol) -> any DataProtocol {
        process(input: input)
    }

    private func process(input: any DataProtocol) -> any DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)

        var processed = 0
        while processed < input.count {
            let keystream = salsa20Block(counter: blockCounter, nonce: nonce, key: key)

            let available = Self.blockSize - offsetInBlock
            let toProcess = min(input.count - processed, available)

            for i in 0..<toProcess {
                let b = input[processed + i] ^ keystream[offsetInBlock + i]
                output.append(b)
            }

            processed += toProcess
            offsetInBlock += toProcess

            if offsetInBlock == Self.blockSize {
                offsetInBlock = 0
                blockCounter += 1
            }
        }

        return output
    }

    private func salsa20Block(counter: UInt64, nonce: any DataProtocol, key: any DataProtocol) -> any DataProtocol {
        let constants: [UInt32] = [
            0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        ]

        let k = stride(from: 0, to: 32, by: 4).map { UInt32(littleEndianBytes: key.slice($0..<$0 + 4)) }
        let n = stride(from: 0, to: 8, by: 4).map { UInt32(littleEndianBytes: nonce.slice($0..<$0 + 4)) }
        let c = [UInt32(counter & 0xFFFFFFFF), UInt32(counter >> 32)]

        var x: [UInt32] = [
            constants[0], k[0], k[1], k[2], k[3], constants[1], n[0], n[1],
            c[0], c[1], constants[2], k[4], k[5], k[6], k[7], constants[3],
        ]

        let original = x

        for _ in 0..<10 {
            quarterRound(&x, 0, 4, 8, 12)
            quarterRound(&x, 5, 9, 13, 1)
            quarterRound(&x, 10, 14, 2, 6)
            quarterRound(&x, 15, 3, 7, 11)
            quarterRound(&x, 0, 1, 2, 3)
            quarterRound(&x, 5, 6, 7, 4)
            quarterRound(&x, 10, 11, 8, 9)
            quarterRound(&x, 15, 12, 13, 14)
        }

        for i in 0..<16 {
            x[i] = x[i] &+ original[i]
        }

        return x.flatMap { $0.bytes() }
    }

    private func quarterRound(_ x: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        x[b] ^= (x[a] &+ x[d]).rotateLeft(7)
        x[c] ^= (x[b] &+ x[a]).rotateLeft(9)
        x[d] ^= (x[c] &+ x[b]).rotateLeft(13)
        x[a] ^= (x[d] &+ x[c]).rotateLeft(18)
    }
}

private extension UInt32 {
    init(littleEndianBytes bytes: any DataProtocol) {
        self = UInt32(bytes[0]) |
            (UInt32(bytes[1]) << 8) |
            (UInt32(bytes[2]) << 16) |
            (UInt32(bytes[3]) << 24)
    }

    func bytes() -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: self & 0xFF),
            UInt8(truncatingIfNeeded: (self >> 8) & 0xFF),
            UInt8(truncatingIfNeeded: (self >> 16) & 0xFF),
            UInt8(truncatingIfNeeded: (self >> 24) & 0xFF),
        ]
    }

    func rotateLeft(_ n: UInt32) -> UInt32 {
        (self << n) | (self >> (32 - n))
    }
}
