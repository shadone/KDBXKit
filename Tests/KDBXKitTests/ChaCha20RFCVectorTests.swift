//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Authoritative correctness anchors for the ChaCha20 stream cipher,
/// independent of the project's self-generated `ChaCha20Tests` vectors.
@Suite("ChaCha20 — RFC 8439 + streaming invariants")
struct ChaCha20RFCVectorTests {
    /// RFC 8439 §2.4.2 worked example. Proves RFC-conformance (not merely
    /// "matches the previous implementation"): a wrong endian handling or
    /// counter placement fails here even if the project KATs still pass.
    @Test("RFC 8439 §2.4.2 known-answer vector")
    func rfc8439Vector() throws {
        let key = Data((0...31).map { UInt8($0) }) // 00 01 02 .. 1f
        let nonce = Data(hexString: "000000000000004a00000000")!
        let plaintext = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let expected = Data(hexString:
            "6e2e359a2568f98041ba0728dd0d6981" +
                "e97e7aec1d4360c20a27afccfd9fae0b" +
                "f91b65c5524733ab8f593dabcd62b357" +
                "1639d624e65152ab8f530c359f0861d8" +
                "07ca0dbf500d6a6156a38e088a22b65e" +
                "52bc514d16ccf806818ce91ab7793736" +
                "5af90bbf74a35be6b40b8eedf2785e42" +
                "874d")!

        // RFC example starts the block counter at 1.
        let cipher = try ChaCha20(key: Array(key), iv: Array(nonce), blockCounter: 1)
        let ciphertext = Data(cipher.encrypt(plaintext))
        #expect(ciphertext == expected)
    }

    /// The keystream must be independent of how the plaintext is chunked
    /// across `encrypt` calls — this exercises the cross-call block-boundary
    /// state (`offsetInBlock` / cached keystream / counter advance), the
    /// part most likely to break in a streaming rewrite.
    @Test("chunking invariance: one-shot == arbitrary chunking")
    func chunkingInvariance() throws {
        let key = Data(hexString: "fd37703ae81a2ef03fb8f666b400fa76aebb0d9ae16cc10dd946fe48170f507f")!
        let nonce = Data(hexString: "9c6f4801e7bb631e9e8ec4a3")!

        // Deterministic pseudo-random plaintext spanning many blocks.
        var lcg: UInt64 = 0x123456789ABCDEF0
        func next() -> UInt8 {
            lcg = lcg &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: lcg >> 33)
        }
        let plaintext = (0..<5000).map { _ in next() }

        let oneShot = Data(try ChaCha20(key: Array(key), iv: Array(nonce)).encrypt(plaintext))

        // Re-encrypt the same plaintext in a variety of chunk schedules,
        // including 1-byte, exactly-64-byte, and ragged boundaries.
        for chunkSizes in [[1], [16], [63], [64], [65], [7, 64, 1, 200, 3], [4096, 904]] {
            let cipher = try ChaCha20(key: Array(key), iv: Array(nonce))
            var out = [UInt8]()
            var i = 0
            var s = 0
            while i < plaintext.count {
                let size = max(1, chunkSizes[s % chunkSizes.count])
                let end = min(i + size, plaintext.count)
                out.append(contentsOf: Array(cipher.encrypt(Array(plaintext[i..<end]))))
                i = end
                s += 1
            }
            #expect(Data(out) == oneShot, "chunk schedule \(chunkSizes) diverged")
        }
    }

    /// Encrypt-then-decrypt with fresh ciphers is the identity, and an empty
    /// input is a no-op that does not advance cipher state.
    @Test("round-trip and empty-input no-op")
    func roundTripAndEmpty() throws {
        let key = Data(hexString: "fd37703ae81a2ef03fb8f666b400fa76aebb0d9ae16cc10dd946fe48170f507f")!
        let nonce = Data(hexString: "9c6f4801e7bb631e9e8ec4a3")!
        let plaintext = Array("the quick brown fox".utf8)

        let enc = try ChaCha20(key: Array(key), iv: Array(nonce))
        #expect(Array(enc.encrypt([])).isEmpty)
        let ct = Array(enc.encrypt(plaintext))
        #expect(Array(enc.encrypt([])).isEmpty) // empty mid-stream: still no-op

        let dec = try ChaCha20(key: Array(key), iv: Array(nonce))
        #expect(Array(dec.decrypt(ct)) == plaintext)
    }
}
