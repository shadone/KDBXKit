//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing

@testable import KDBXKit

struct HeaderTests {
    @Test
    func formatVersion_4_0() {
        let version = Header.FormatVersion(rawValue: 0x00040000)
        #expect(version.major == 4)
        #expect(version.minor == 0)
        #expect(version == .v4_0)
        #expect(version.rawValue == 0x40000)
    }

    @Test
    func formatVersion_4_1() {
        let version = Header.FormatVersion(rawValue: 0x00040001)
        #expect(version.major == 4)
        #expect(version.minor == 1)
        #expect(version == .v4_1)
        #expect(version.rawValue == 0x40001)
    }

    @Test
    func writeThenRead() async throws {
        // must be 32 bytes for AES256
        let masterSalt = Data([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ])
        // must be 16 bytes for AES256
        let nonce = Data([
            42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        ])

        let header = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: .AES256CBC,
            compressionAlgorithm: .gzip,
            masterSalt: masterSalt,
            encryptionNonce: nonce,
            kdfParameters: .argon2d(
                .init(
                    version: .v1_3,
                    salt: Data([4, 5, 6]),
                    iterations: 1_234_567,
                    memory: 987_654_321,
                    parallelism: 424_242
                ),
                additional: [
                    "Foo": .string("Bar"),
                ],
            ),
            publicCustomData: [
                "Hello": .string("World"),
            ],
        )

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try HeaderWriter(to: outputStream).write(header)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var reader = HeaderReader(data: data)
        let (parsed, headerLength) = try reader.parse()

        #expect(parsed == header)
        #expect(headerLength == data.count)
    }

    @Test("Empty publicCustomData is omitted on write and round-trips to [:]")
    func emptyPublicCustomDataOmitted() throws {
        let header = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: .AES256CBC,
            compressionAlgorithm: .gzip,
            masterSalt: Data(repeating: 1, count: 32),
            encryptionNonce: Data(repeating: 2, count: 16),
            kdfParameters: .aes(.init(salt: Data(repeating: 3, count: 32), rounds: 1), additional: [:]),
            publicCustomData: [:]
        )
        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try HeaderWriter(to: outputStream).write(header)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // The PublicCustomData field type byte (0x0C) must not appear as a
        // header field — KeePass omits an empty one.
        #expect(!data.contains(HeaderFieldType.publicCustomData.rawValue))

        var reader = HeaderReader(data: data)
        let (parsed, _) = try reader.parse()
        #expect(parsed.publicCustomData.isEmpty)
    }

    @Test("KDF VariantDictionary serialization is deterministic regardless of key insertion order")
    func variantDictionaryDeterministicOrder() throws {
        func headerData(additionalOrder reversed: Bool) throws -> Data {
            let pairs: [(String, VariantDictionaryValue)] = [
                ("Alpha", .string("1")),
                ("Bravo", .uint32(2)),
                ("Charlie", .bytes(Data([3]))),
            ]
            var additional: VariantDictionary = [:]
            for (k, v) in reversed ? pairs.reversed() : pairs {
                additional[k] = v
            }
            let header = Header(
                formatVersion: .v4_1,
                encryptionAlgorithm: .AES256CBC,
                compressionAlgorithm: .gzip,
                masterSalt: Data(repeating: 1, count: 32),
                encryptionNonce: Data(repeating: 2, count: 16),
                kdfParameters: .aes(.init(salt: Data(repeating: 3, count: 32), rounds: 1), additional: additional),
                publicCustomData: [:]
            )
            let outputStream = OutputStream(toMemory: ())
            outputStream.open()
            try HeaderWriter(to: outputStream).write(header)
            return outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        }
        #expect(try headerData(additionalOrder: false) == headerData(additionalOrder: true))
    }
}
