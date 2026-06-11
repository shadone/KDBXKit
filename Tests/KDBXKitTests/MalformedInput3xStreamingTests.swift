//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Extends the crash-free / typed-error guarantee of `MalformedInputTests`
/// (4.x eager only) to the KDBX 3.1 read path and the streaming opens. A
/// corrupted vault on any of these paths must produce a typed error, never
/// a process trap.
@Suite("Malformed input — KDBX 3.1 and streaming paths")
struct MalformedInput3xStreamingTests {
    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: URL(filePath: Bundle.module.path(forResource: "Resources/\(name)", ofType: "kdbx")!))
    }

    // MARK: KDBX 3.1 eager

    @Test("Truncating a 3.1 file at every boundary throws cleanly")
    func truncate3x() throws {
        let good = try fixture("kpxc-kdbx31-default")
        let unlock = UnlockData(masterPassword: "test")
        _ = try KDBXReader.parse(good, unlockData: unlock) // sanity

        for length in stride(from: 0, to: good.count, by: 128) {
            let truncated = good.prefix(length)
            #expect(throws: (any Error).self) {
                _ = try KDBXReader.parse(Data(truncated), unlockData: unlock)
            }
        }
    }

    @Test("Bit-flips across a 3.1 file are rejected, never trap")
    func bitFlip3x() throws {
        let good = try fixture("kpxc-kdbx31-default")
        let unlock = UnlockData(masterPassword: "test")

        // Flip one byte at a spread of offsets (header fields, transform
        // seed region, StreamStartBytes, block stream, body). Every flip
        // must throw a typed error rather than crash; a few interior flips
        // could in principle still parse (e.g. inside slack), so we only
        // assert no-trap, not that every flip is detected.
        for offset in stride(from: 8, to: good.count, by: 137) {
            var data = good
            data[offset] ^= 0xFF
            _ = try? KDBXReader.parse(data, unlockData: unlock)
        }
    }

    @Test("A 3.1 header truncated mid-field throws, not a trap")
    func truncated3xHeaderField() throws {
        let good = try fixture("kpxc-kdbx31-default")
        // Cut inside the header (well before the StreamStartBytes /
        // block stream) so a TLV length runs past the available bytes.
        let cut = good.prefix(20)
        #expect(throws: (any Error).self) {
            _ = try KDBXReader.parse(Data(cut), unlockData: .init(masterPassword: "test"))
        }
    }

    // MARK: Streaming opens

    @Test("Truncating a 4.x file at every boundary throws on the streaming open")
    func truncateStreaming() throws {
        let good = try fixture("simple-argon2id-aes256")
        let unlock = UnlockData(masterPassword: "123")
        _ = try KDBXReader.openMetadataStreaming(from: .data(good), unlockData: unlock) // sanity

        for length in stride(from: 0, to: good.count, by: 128) {
            let truncated = Data(good.prefix(length))
            #expect(throws: (any Error).self) {
                _ = try KDBXReader.openMetadataStreaming(from: .data(truncated), unlockData: unlock)
            }
        }
    }

    @Test("Bit-flips are rejected on both lazy opens, never trap")
    func bitFlipLazyOpens() throws {
        let good = try fixture("simple-argon2id-aes256")
        let unlock = UnlockData(masterPassword: "123")

        for offset in stride(from: 8, to: good.count, by: 113) {
            var data = good
            data[offset] ^= 0xFF
            _ = try? KDBXReader.openMetadataStreaming(from: .data(data), unlockData: unlock)
            _ = try? KDBXReader.openMetadataOnly(from: .data(data), unlockData: unlock)
        }
    }

    @Test("Garbage and empty input throw on the streaming open")
    func garbageStreaming() {
        let unlock = UnlockData(masterPassword: "123")
        #expect(throws: (any Error).self) {
            _ = try KDBXReader.openMetadataStreaming(from: .data(Data()), unlockData: unlock)
        }
        #expect(throws: (any Error).self) {
            _ = try KDBXReader.openMetadataStreaming(
                from: .data(Data(repeating: 0xAB, count: 512)), unlockData: unlock
            )
        }
    }
}
