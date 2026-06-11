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
    // MARK: GzipStreamReader — unit

    @Test("Decompress with a tight cap throws .outputTooLarge")
    func tinyCap_throwsOutputTooLarge() throws {
        // Produce a gzip stream that decompresses to far more than the cap.
        let plaintext = Data(repeating: 0x41, count: 10000)
        let gz = try GzipOneShot.compress(plaintext)

        do {
            _ = try GzipStreamReader.decompress(gz, maxOutputBytes: 100)
            Issue.record("Expected .outputTooLarge")
        } catch let ZlibError.outputTooLarge(limit) {
            #expect(limit == 100)
        } catch {
            Issue.record("Wrong error: \(error)")
        }
    }

    @Test("Decompress under the cap succeeds and returns the full payload")
    func underCap_succeeds() throws {
        let plaintext = Data(repeating: 0x41, count: 100)
        let gz = try GzipOneShot.compress(plaintext)
        let out = try GzipStreamReader.decompress(gz, maxOutputBytes: 1024)
        #expect(out == plaintext)
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
        } catch {
            if case let .decompressedPayloadTooLarge(limit) = error {
                #expect(limit == 1)
            } else {
                Issue.record("Wrong error: \(error)")
            }
        }
    }

    @Test("Streaming open with a 1-byte cap throws .decompressedPayloadTooLarge, not internal ZlibError")
    func tinyCap_throwsTypedErrorStreaming() throws {
        let kdbxPath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: kdbxPath))

        // The streaming path must surface the same public typed error the
        // eager path maps to — a consumer switching on KDBXReader.Error
        // must not receive the internal ZlibError type.
        do {
            _ = try KDBXReader.openMetadataStreaming(
                from: .data(data),
                unlockData: .init(masterPassword: "123"),
                maxDecompressedPayloadSize: 1
            )
            Issue.record("Expected .decompressedPayloadTooLarge")
        } catch let error as KDBXReader.Error {
            if case let .decompressedPayloadTooLarge(limit) = error {
                #expect(limit == 1)
            } else {
                Issue.record("Wrong error case: \(error)")
            }
        } catch {
            Issue.record("Internal error type escaped the public API: \(error)")
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
