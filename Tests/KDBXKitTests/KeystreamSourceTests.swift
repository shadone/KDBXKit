//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KeystreamSource — random-access matches linear-walk byte-for-byte")
struct KeystreamSourceTests {
    @Test("ChaCha20: decrypting a slice at offset O matches linear walk position O")
    func chacha20RandomAccessMatchesLinear() throws {
        let keyBytes = Data((0..<32).map { UInt8($0) })
        let nonce = Data((0..<12).map { UInt8($0 + 0x40) })
        let plaintext = Data((0..<512).map { UInt8($0 & 0xFF) })

        // Encrypt the whole stream linearly to get the reference ciphertext.
        let referenceCipher = try ChaCha20(key: keyBytes, iv: nonce)
        let ciphertext = Data(Array(referenceCipher.encrypt(plaintext) as! [UInt8]))

        let source = KeystreamSource(
            algorithm: .chacha20,
            key: SecureBytes(keyBytes),
            nonce: nonce
        )

        // Decrypt arbitrary slices at arbitrary offsets and confirm
        // they match the corresponding bytes of `plaintext`.
        let slices: [(offset: Int, length: Int)] = [
            (0, 1), (0, 64), (0, 65), // block boundary
            (32, 16), // mid-block
            (63, 2), // straddles a block boundary
            (128, 64), // exact block
            (200, 100), // multi-block, mid-block start
            (511, 1), // last byte
        ]

        for (offset, length) in slices {
            let slice = ciphertext.subdata(in: offset..<(offset + length))
            let decrypted = source.decrypt(ciphertext: slice, at: offset)
            let bytes = decrypted.withUnsafeBytes { Data($0) }
            #expect(
                bytes == plaintext.subdata(in: offset..<(offset + length)),
                "Mismatch at offset \(offset), length \(length)"
            )
        }
    }

    @Test("Salsa20: decrypting a slice at offset O matches linear walk position O")
    func salsa20RandomAccessMatchesLinear() throws {
        let keyBytes = Data((0..<32).map { UInt8($0 * 7 & 0xFF) })
        let nonce = Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])
        let plaintext = Data((0..<384).map { UInt8(($0 + 5) & 0xFF) })

        let referenceCipher = try Salsa20(key: keyBytes, iv: nonce)
        let ciphertext = Data(Array(referenceCipher.encrypt(plaintext) as! [UInt8]))

        let source = KeystreamSource(
            algorithm: .salsa20,
            key: SecureBytes(keyBytes),
            nonce: nonce
        )

        let slices: [(offset: Int, length: Int)] = [
            (0, 1), (0, 64), (0, 65),
            (10, 50),
            (64, 64),
            (60, 8),
            (300, 50),
            (383, 1),
        ]

        for (offset, length) in slices {
            let slice = ciphertext.subdata(in: offset..<(offset + length))
            let decrypted = source.decrypt(ciphertext: slice, at: offset)
            let bytes = decrypted.withUnsafeBytes { Data($0) }
            #expect(
                bytes == plaintext.subdata(in: offset..<(offset + length)),
                "Mismatch at offset \(offset), length \(length)"
            )
        }
    }

    @Test("Decrypting an empty slice returns empty bytes regardless of offset")
    func emptySliceIsEmpty() {
        let source = KeystreamSource(
            algorithm: .chacha20,
            key: SecureBytes(Data(repeating: 0xAB, count: 32)),
            nonce: Data(repeating: 0xCD, count: 12)
        )
        let result = source.decrypt(ciphertext: Data(), at: 12345)
        #expect(result.withUnsafeBytes { Data($0) }.isEmpty)
    }
}
