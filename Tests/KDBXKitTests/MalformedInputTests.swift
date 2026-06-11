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

    // MARK: - Negative / empty length fields (no reversed-range traps)

    /// Locate the first HMAC block's `size` field in a known-good 4.x file.
    /// Layout after the outer header: header SHA-256 (32) ‖ header HMAC (32)
    /// ‖ [ block HMAC (32) ‖ size (Int32 LE) ‖ block ]. The block size is a
    /// *signed* Int32 on the wire; a high-bit value reads back negative.
    private func firstBlockSizeFieldOffset(in data: Data) throws -> Int {
        var reader = HeaderReader(data: data)
        let (_, headerLength) = try reader.parse()
        return headerLength + 32 + 32 + 32
    }

    /// A 4.x block whose `size` field has the high bit set decodes to a
    /// negative `Int32`. `readData(length: Int(size))` then built a reversed
    /// `start..<end` Range and trapped the process — and crucially this read
    /// happens *before* the per-block HMAC check, so a corrupted (or
    /// hostile) vault opened with the correct password aborted instead of
    /// returning a typed error. Must be a clean throw on the eager path.
    @Test("Negative 4.x block-stream size is rejected, not a reversed-range trap (eager)")
    func negativeBlockSizeThrowsEager() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))

        let off = try firstBlockSizeFieldOffset(in: data)
        data[off] = 0xFF
        data[off + 1] = 0xFF
        data[off + 2] = 0xFF
        data[off + 3] = 0xFF

        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        }
    }

    /// Companion: the lazy / streaming block loop shares the same signed
    /// `size` read (`readDataPublic`), so it must reject the same input
    /// rather than trap.
    @Test("Negative 4.x block-stream size is rejected, not a reversed-range trap (streaming)")
    func negativeBlockSizeThrowsStreaming() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        var data = try Data(contentsOf: URL(filePath: path))

        let off = try firstBlockSizeFieldOffset(in: data)
        data[off] = 0xFF
        data[off + 1] = 0xFF
        data[off + 2] = 0xFF
        data[off + 3] = 0xFF

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-negblock-\(UUID().uuidString).kdbx")
        try data.write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.openMetadataStreaming(
                from: .file(tmp),
                unlockData: .init(masterPassword: "123")
            )
        }
    }

    /// An inner-header `binaryContent` (type 3) field with length 0 carries
    /// no flags byte. The parser indexed `valueData[valueData.startIndex]`
    /// unconditionally and trapped on the empty value. Must throw instead.
    @Test("Empty inner-header binaryContent field is rejected, not an empty-subscript trap")
    func emptyInnerBinaryContentThrows() {
        // TLV: type=3 (binaryContent) ‖ Int32 length=0 ‖ (no value).
        var reader = InnerHeaderReader(data: Data([3, 0, 0, 0, 0]))
        #expect(throws: InnerHeaderReader.Error.self) {
            _ = try reader.parse()
        }
    }

    /// An inner-header field length is a signed `Int32` on the wire; a
    /// high-bit value reads back negative and hit the same reversed-range
    /// trap as the outer block size. Must throw.
    @Test("Negative inner-header field length is rejected, not a reversed-range trap")
    func negativeInnerFieldLengthThrows() {
        // TLV: type=3 ‖ Int32 length=0xFFFFFFFF (-1) ‖ (no value).
        var reader = InnerHeaderReader(data: Data([3, 0xFF, 0xFF, 0xFF, 0xFF]))
        #expect(throws: InnerHeaderReader.Error.self) {
            _ = try reader.parse()
        }
    }

    /// `AESKDF.derive` preconditions on a 32-byte salt, and the unlock key
    /// is computed *before* the header HMAC check — so a crafted header with
    /// a wrong-size `S` field would abort the process pre-authentication
    /// unless the salt is rejected at parse. (The 3.x route already
    /// validates its `TransformSeed` to 32 bytes.)
    @Test("AES-KDF parameters with a wrong-size salt are rejected at parse, not a precondition trap")
    func aesKDFWrongSaltLengthRejected() {
        let aesUUID = KDFParameters.KDF.AES.toUInt128().toDataLittleEndian()
        for badLength in [0, 16, 31, 33, 64] {
            let params: VariantDictionary = [
                "$UUID": .bytes(aesUUID),
                "S": .bytes(Data(repeating: 0xAB, count: badLength)),
                "R": .uint64(1000),
            ]
            #expect(KDFParameters(from: params) == nil, "salt length \(badLength) must be rejected")
        }

        // The valid length stays accepted.
        let valid: VariantDictionary = [
            "$UUID": .bytes(aesUUID),
            "S": .bytes(Data(repeating: 0xAB, count: 32)),
            "R": .uint64(1000),
        ]
        #expect(KDFParameters(from: valid) != nil)
    }
}
