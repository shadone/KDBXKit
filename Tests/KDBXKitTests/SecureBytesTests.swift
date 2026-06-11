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

    @Test("Memory is zeroed when a SecureBytes is released")
    func zeroesOnDeinit() {
        // The core promise of the type. Testable because a shared arena
        // keeps its pages mapped after one slot is freed: hold a sibling
        // secret so the arena (and the released slot's page) stays alive,
        // capture the slot's address while the secret is live, drop it,
        // then re-read the same region and assert it's all zero.
        let sibling = SecureBytes(Data(repeating: 0xAA, count: 16))

        let marker = [UInt8](repeating: 0x5A, count: 48)
        var captured: UnsafeRawPointer?
        var length = 0
        do {
            let secret = SecureBytes(marker)
            secret.withUnsafeBytes { buf in
                captured = buf.baseAddress
                length = buf.count
                #expect(buf.contains(0x5A)) // content is present while live
            }
        } // `secret` deinits here — its slot must be zeroed

        let base = try! #require(captured).assumingMemoryBound(to: UInt8.self)
        let after = UnsafeBufferPointer(start: base, count: length)
        #expect(after.allSatisfy { $0 == 0 }, "released SecureBytes slot was not zeroed")

        // Keep the arena (and thus the page we just read) alive across the
        // read above.
        withExtendedLifetime(sibling) { }
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

    @Test("A secret larger than the arena threshold round-trips")
    func dedicatedLargeSecret() {
        // 200 KiB exceeds the arena's large-secret threshold, so it lands in
        // its own dedicated mlock'd region rather than the shared arena.
        let bytes = (0..<(200 * 1024)).map { UInt8($0 & 0xFF) }
        let s = SecureBytes(bytes)
        #expect(s.count == bytes.count)
        #expect(s.toData() == Data(bytes))
    }

    @Test("Mixed-size secrets coexisting in arenas all round-trip")
    func mixedSizesRoundTrip() {
        var held: [(SecureBytes, [UInt8])] = []
        for i in 0..<500 {
            let len = (i * 7) % 300 // 0..299, mix of empty and small
            let bytes = (0..<len).map { UInt8(($0 &+ i) & 0xFF) }
            held.append((SecureBytes(bytes), bytes))
        }
        for (secure, expected) in held {
            #expect(secure.count == expected.count)
            #expect(Array(secure.toData()) == expected)
        }
    }
}

// These tests use a private `SecureBytesArenaAllocator` instance rather than
// the process-global one, so concurrently-running suites (which allocate
// SecureBytes constantly) can't perturb the measurements.
@Suite("SecureBytes — arena allocator")
struct SecureBytesArenaTests {
    @Test("Small secrets pack into shared arenas, not one per secret")
    func packsManySecretsPerArena() {
        let allocator = SecureBytesArenaAllocator()
        var arenaIDs = Set<ObjectIdentifier>()
        let n = 4000
        for _ in 0..<n {
            let (arena, _) = allocator.allocate(24)
            arenaIDs.insert(ObjectIdentifier(arena))
        }
        // 24 B rounds to a 32 B slot; n * 32 B = 128 KiB across 64 KiB
        // arenas is a literal handful — nowhere near `n`. Pre-arena this
        // wired effectively one page per secret, which is the bug.
        #expect(arenaIDs.count < n / 100)
    }

    @Test("Wired arena memory stays proportional to the data, not the count")
    func wiredMemoryProportionalToData() {
        let allocator = SecureBytesArenaAllocator()
        var arenas: [SecureArena] = []
        var seen = Set<ObjectIdentifier>()
        let n = 4000
        for _ in 0..<n {
            let (arena, _) = allocator.allocate(24)
            if seen.insert(ObjectIdentifier(arena)).inserted {
                arenas.append(arena) // hold so we can sum sizes
            }
        }
        let wired = arenas.reduce(0) { $0 + $1.size }
        // ~96 KiB of payload; wired is a small multiple of that, NOT
        // n * pageSize (which would be tens of MB).
        #expect(wired < 1024 * 1024)
    }

    @Test("Large secrets get their own dedicated arena")
    func largeSecretsAreDedicated() {
        let allocator = SecureBytesArenaAllocator()
        let big = allocator.largeThreshold + 1
        let (a1, _) = allocator.allocate(big)
        let (a2, _) = allocator.allocate(big)
        #expect(ObjectIdentifier(a1) != ObjectIdentifier(a2))
        #expect(a1.size >= big)
    }

    @Test("Concurrent construction from many tasks is safe")
    func concurrentConstruction() async {
        // Exercises the global allocator's lock under contention plus the
        // lock-free read path. Asserts correctness, not memory.
        await withTaskGroup(of: Bool.self) { group in
            for i in 0..<2000 {
                group.addTask {
                    let payload = "secret-\(i)-value"
                    let s = SecureBytes(utf8: payload)
                    return s.revealedString == payload && s.count == payload.utf8.count
                }
            }
            for await ok in group {
                #expect(ok)
            }
        }
    }
}
