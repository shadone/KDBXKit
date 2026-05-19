//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("SecureBytes — basic correctness")
struct SecureBytesTests {
    @Test("Roundtrips through UTF-8 / Data / [UInt8]")
    func roundtrips() {
        let s = SecureBytes(utf8: "hunter2")
        #expect(s.count == 7)
        #expect(s.toData() == Data("hunter2".utf8))
        s.withRevealedString { revealed in
            #expect(revealed == "hunter2")
        }
        #expect(s.revealedString == "hunter2")
    }

    @Test("Empty bytes")
    func empty() {
        let s = SecureBytes.empty
        #expect(s.isEmpty)
        #expect(s.toData().isEmpty)
        #expect(s.revealedString.isEmpty)
    }

    @Test("Equality on contents, not identity")
    func equality() {
        let a = SecureBytes(utf8: "abc")
        let b = SecureBytes(utf8: "abc")
        let c = SecureBytes(utf8: "abd")
        #expect(a == b)
        #expect(a != c)
        #expect(a !== b) // different objects, equal contents
    }

    @Test("Description doesn't leak content")
    func descriptionIsSafe() {
        let s = SecureBytes(utf8: "super-secret-password")
        let desc = String(describing: s)
        #expect(!desc.contains("super"))
        #expect(!desc.contains("password"))
        #expect(desc.contains("count="))
    }

    @Test("Round-trip 1 KB of random bytes")
    func largeBuffer() {
        let bytes = (0..<1024).map { _ in UInt8.random(in: 0...255) }
        let s = SecureBytes(bytes)
        #expect(s.count == 1024)
        #expect(s.toData() == Data(bytes))
    }

    @Test("Hashable conformance hashes by length, not content")
    func hashLeak() {
        // Two SecureBytes with the same length but different content should
        // produce the same hash — the API contract is "don't leak content
        // through the hash."
        let a = SecureBytes(utf8: "abcdef")
        let b = SecureBytes(utf8: "ghijkl")
        var hA = Hasher()
        a.hash(into: &hA)
        var hB = Hasher()
        b.hash(into: &hB)
        #expect(hA.finalize() == hB.finalize())
    }
}
