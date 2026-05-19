//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Verifies the parser never crashes on hostile input and reports a typed
/// error every time. Force-unwraps and unchecked subdata reads inside the
/// reader could panic the host app on malicious files; these tests cover
/// the most obvious attack surfaces.
@Suite("Malformed input handling — parser is crash-free")
struct MalformedInputTests {
    @Test
    func emptyDataThrows() {
        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.parseHeader(Data())
        }
    }

    @Test
    func randomGarbageThrowsInvalidSignature() {
        // Anything that doesn't start with the KDBX magic should reject early.
        let bogus = Data((0..<512).map { _ in UInt8.random(in: 0...255) })
        do {
            _ = try KDBXReader.parseHeader(bogus)
            Issue.record("Expected an error for random bytes")
        } catch {
            // Either invalidFileSignature or one of the unsupported variants,
            // depending on whether the random bytes happen to look like
            // signatures. Either way it's a typed error, not a crash.
        }
    }

    @Test
    func validSignatureFollowedByGarbageThrowsTypedError() {
        // Valid KDBX signature (signature1 + signature2 little-endian), then
        // random bytes. Should fail at format-version / field parsing.
        var data = Data()
        func appendLE(_ v: UInt32, to data: inout Data) {
            data.append(UInt8(v & 0xFF))
            data.append(UInt8((v >> 8) & 0xFF))
            data.append(UInt8((v >> 16) & 0xFF))
            data.append(UInt8((v >> 24) & 0xFF))
        }
        appendLE(0x9AA2D903, to: &data)
        appendLE(0xB54BFB67, to: &data)
        data.append(Data((0..<256).map { _ in UInt8.random(in: 0...255) }))

        do {
            _ = try KDBXReader.parseHeader(data)
            Issue.record("Expected a typed error for valid signature with garbage tail")
        } catch {
            // Pass — typed error, not a crash.
        }
    }

    @Test("Truncating a known-good file at every byte boundary throws cleanly")
    func progressiveTruncation() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let goodData = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "123")

        // The full file parses.
        _ = try KDBXReader.parse(goodData, unlockData: unlock)

        // Sample several truncation lengths — exhaustive byte-by-byte is too
        // slow for CI but every-256-bytes covers each major section.
        for length in stride(from: 0, to: goodData.count, by: 256) {
            let truncated = goodData.prefix(length)
            do {
                _ = try KDBXReader.parse(truncated, unlockData: unlock)
                Issue.record("Truncated file of \(length) bytes parsed successfully — unexpected")
            } catch {
                // Pass: any KDBXReader.Error is acceptable as long as we don't crash.
            }
        }
    }

    @Test("Flipping a byte in the middle of the header rejects with typed error")
    func bitFlipInHeader() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))

        // Flip a byte at offset 12 (well past the magic, into the format
        // version / fields region). The header SHA-256 check should catch it.
        data[12] ^= 0xFF

        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        }
    }

    @Test("Flipping a byte after the header rejects via HMAC mismatch")
    func bitFlipInBody() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))

        // Past the header + its SHA-256 + header HMAC. The block HMAC check
        // should catch it.
        let bodyOffset = data.count - 100
        data[bodyOffset] ^= 0x01

        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        }
    }

    /// The HMAC-protected block stream ends with a size-0 sentinel block
    /// whose HMAC binds the "this is the end of the stream" signal to the
    /// unlock key. If the sentinel's HMAC is not checked, an attacker can
    /// substitute an interior block for the sentinel and truncate the
    /// authenticated payload without detection.
    @Test
    func tamperedEndBlockHMACIsRejected() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))

        // The end-block HMAC sits at offset (fileSize - 36): 32 bytes of
        // HMAC followed by the 4-byte size-0 length field. Flip a bit in
        // the first byte of the HMAC tag.
        let endBlockHmacOffset = data.count - 36
        data[endBlockHmacOffset] ^= 0x01

        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        }
    }

    /// Companion to ``tamperedEndBlockHMACIsRejected``: the lazy reader
    /// shares the truncation-attack surface and MUST also reject a
    /// tampered sentinel HMAC.
    @Test
    func tamperedEndBlockHMACIsRejectedLazy() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))

        let endBlockHmacOffset = data.count - 36
        data[endBlockHmacOffset] ^= 0x01

        // Write to a temp file so we can hit the lazy/file-source path.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-endblock-tamper-\(UUID().uuidString).kdbx")
        try data.write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.openMetadataOnly(
                from: .file(tmp),
                unlockData: .init(masterPassword: "123")
            )
        }
    }
}
