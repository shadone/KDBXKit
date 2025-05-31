//
//  CryptoSwift
//
//  Copyright (C) 2014-2025 Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  Copyright (C) 2025 Denis Dzyubenko <denis@ddenis.info>
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

fileprivate extension DataProtocol {
    func slice(_ range: Range<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: range.lowerBound)
        let end = index(startIndex, offsetBy: range.upperBound)
        return self[start..<end]
    }

    subscript(position: Int) -> Element {
        self[index(startIndex, offsetBy: position)]
    }
}

fileprivate extension MutableDataProtocol {
    mutating func replaceSubrange<C>(_ subrange: Range<Int>, with newElements: C) where C : Collection, Element == C.Element {
        let start = index(startIndex, offsetBy: subrange.lowerBound)
        let end = index(startIndex, offsetBy: subrange.upperBound)
        replaceSubrange(start..<end, with: newElements)
    }
}

extension UInt32 {
    init<T: DataProtocol>(bytes: T) {
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
    private let key: any DataProtocol
    private let nonce: any DataProtocol
    private var blockCounter: UInt32
    private var offsetInBlock: Int = 0

    public init(key: any DataProtocol, iv nonce: any DataProtocol, blockCounter: UInt32 = 0) throws {
        guard key.count == 32 else {
            throw NSError(domain: "ChaCha20", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid key length"])
        }
        guard nonce.count == 12 else {
            throw NSError(domain: "ChaCha20", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid nonce length"])
        }

        self.key = key
        self.nonce = nonce
        self.blockCounter = blockCounter
    }

    public func encrypt(_ input: any DataProtocol) -> any DataProtocol {
        return process(input: input)
    }

    public func decrypt(_ input: any DataProtocol) -> any DataProtocol {
        return process(input: input)
    }

    private func process(input: any DataProtocol) -> any DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)

        var processed = 0
        let total = input.count

        while processed < total {
            // Construct counter block: 4 bytes counter + 12 bytes nonce
            let counterBlock = blockCounter.bigEndian.bytes() + nonce
            var keystream: any MutableDataProtocol = [UInt8](repeating: 0, count: Self.blockSize)
            core(block: &keystream, counter: counterBlock, key: key)

            let offset = offsetInBlock
            let available = Self.blockSize - offset
            let bytesToProcess = min(available, total - processed)

            for i in 0..<bytesToProcess {
                output.append(input[processed + i] ^ keystream[offset + i])
            }

            processed += bytesToProcess
            offsetInBlock += bytesToProcess

            if offsetInBlock == Self.blockSize {
                blockCounter += 1
                offsetInBlock = 0
            }
        }

        return output
    }

    /// https://tools.ietf.org/html/rfc7539#section-2.3.
    fileprivate func core(block: inout any MutableDataProtocol, counter: any DataProtocol, key: any DataProtocol) {
      precondition(block.count == ChaCha20.blockSize)
      precondition(counter.count == 16)
      precondition(key.count == 32)

      let j0: UInt32 = 0x61707865
      let j1: UInt32 = 0x3320646e // 0x3620646e sigma/tau
      let j2: UInt32 = 0x79622d32
      let j3: UInt32 = 0x6b206574

      let j4: UInt32 = UInt32(bytes: key.slice(0..<4)).bigEndian
      let j5: UInt32 = UInt32(bytes: key.slice(4..<8)).bigEndian
      let j6: UInt32 = UInt32(bytes: key.slice(8..<12)).bigEndian
      let j7: UInt32 = UInt32(bytes: key.slice(12..<16)).bigEndian
      let j8: UInt32 = UInt32(bytes: key.slice(16..<20)).bigEndian
      let j9: UInt32 = UInt32(bytes: key.slice(20..<24)).bigEndian
      let j10: UInt32 = UInt32(bytes: key.slice(24..<28)).bigEndian
      let j11: UInt32 = UInt32(bytes: key.slice(28..<32)).bigEndian
      let j12: UInt32 = UInt32(bytes: counter.slice(0..<4)).bigEndian
      let j13: UInt32 = UInt32(bytes: counter.slice(4..<8)).bigEndian
      let j14: UInt32 = UInt32(bytes: counter.slice(8..<12)).bigEndian
      let j15: UInt32 = UInt32(bytes: counter.slice(12..<16)).bigEndian

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

      block.replaceSubrange(0..<4, with: x0.bigEndian.bytes())
      block.replaceSubrange(4..<8, with: x1.bigEndian.bytes())
      block.replaceSubrange(8..<12, with: x2.bigEndian.bytes())
      block.replaceSubrange(12..<16, with: x3.bigEndian.bytes())
      block.replaceSubrange(16..<20, with: x4.bigEndian.bytes())
      block.replaceSubrange(20..<24, with: x5.bigEndian.bytes())
      block.replaceSubrange(24..<28, with: x6.bigEndian.bytes())
      block.replaceSubrange(28..<32, with: x7.bigEndian.bytes())
      block.replaceSubrange(32..<36, with: x8.bigEndian.bytes())
      block.replaceSubrange(36..<40, with: x9.bigEndian.bytes())
      block.replaceSubrange(40..<44, with: x10.bigEndian.bytes())
      block.replaceSubrange(44..<48, with: x11.bigEndian.bytes())
      block.replaceSubrange(48..<52, with: x12.bigEndian.bytes())
      block.replaceSubrange(52..<56, with: x13.bigEndian.bytes())
      block.replaceSubrange(56..<60, with: x14.bigEndian.bytes())
      block.replaceSubrange(60..<64, with: x15.bigEndian.bytes())
    }
}

fileprivate extension UInt32 {
    func bytes() -> [UInt8] {
        [
            UInt8((self >> 24) & 0xff),
            UInt8((self >> 16) & 0xff),
            UInt8((self >> 8) & 0xff),
            UInt8(self & 0xff),
        ]
    }
}
