//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("Decompression cap — defensive bound against unbounded inflation")
struct DecompressionCapTests {

    // MARK: CappedDataOutputStream — unit

    @Test("Writes under the cap succeed and accumulate")
    func underCap_accumulates() {
        let stream = CappedDataOutputStream(cap: 10)
        let written = "hello".utf8.withContiguousStorageIfAvailable { buffer -> Int in
            stream.write(buffer.baseAddress!, maxLength: buffer.count)
        }
        #expect(written == 5)
        #expect(stream.collected.count == 5)
        #expect(stream.overflowed == false)
    }

    @Test("Write that crosses the cap is rejected with -1")
    func overCap_rejected() {
        let stream = CappedDataOutputStream(cap: 3)
        let written = "hello".utf8.withContiguousStorageIfAvailable { buffer -> Int in
            stream.write(buffer.baseAddress!, maxLength: buffer.count)
        }
        #expect(written == -1)
        #expect(stream.overflowed)
    }

    @Test("Exactly-at-cap write succeeds; one past the cap is rejected")
    func boundaryCases() {
        let stream = CappedDataOutputStream(cap: 5)
        _ = "hello".utf8.withContiguousStorageIfAvailable { buffer -> Int in
            stream.write(buffer.baseAddress!, maxLength: buffer.count)
        }
        #expect(stream.collected.count == 5)
        #expect(stream.overflowed == false)

        let again = "x".utf8.withContiguousStorageIfAvailable { buffer -> Int in
            stream.write(buffer.baseAddress!, maxLength: buffer.count)
        }
        #expect(again == -1)
        #expect(stream.overflowed)
    }

    // MARK: KDBXReader integration

    @Test("Reading a real fixture with a 1-byte cap throws .decompressedPayloadTooLarge")
    func tinyCap_throwsTypedError() throws {
        let kdbxPath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: kdbxPath))
        var reader = KDBXReader(data)

        // Tight cap guarantees overflow on the very first chunk.
        do {
            _ = try reader.parse(unlockData: .init(masterPassword: "123"), maxDecompressedPayloadSize: 1)
            Issue.record("Expected .decompressedPayloadTooLarge")
        } catch let error as KDBXReader.Error {
            if case let .decompressedPayloadTooLarge(limit) = error {
                #expect(limit == 1)
            } else {
                Issue.record("Wrong error: \(error)")
            }
        }
    }

    @Test("Reading a real fixture with the default cap succeeds")
    func defaultCap_succeeds() throws {
        // Sanity guard: changing the default cap to something silly (e.g.
        // 0 or smaller than real-world vaults) breaks every consumer. This
        // test wedges it against the bundled fixtures.
        let kdbxPath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: kdbxPath))
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        #expect(content.database.meta.databaseName != nil)
    }
}
