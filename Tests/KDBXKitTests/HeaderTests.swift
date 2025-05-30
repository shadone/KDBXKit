//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Testing
import Foundation

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
                    iterations: 1234567,
                    memory: 987654321,
                    parallelism: 424242
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
}
