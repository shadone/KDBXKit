//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBXContent.makeEmpty — fresh vault factory")
struct MakeEmptyTests {
    @Test("makeEmpty produces a writeable + reparseable vault")
    func writeRoundtrip() throws {
        let content = KDBXContent.makeEmpty(databaseName: "Test")
        let unlock = UnlockData(masterPassword: "pw")

        // Round-trip: write to memory, then read back.
        let stream = OutputStream(toMemory: ())
        stream.open()
        try KDBXWriter(to: stream).write(content, unlockData: unlock)
        let data = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        stream.close()

        let reopened = try KDBXReader.parse(data, unlockData: unlock)

        // Same database name, same root group UUID, no entries yet.
        #expect(reopened.database.meta.databaseName == "Test")
        #expect(reopened.database.root.group.uuid == content.database.root.group.uuid)
        #expect(reopened.database.root.group.entries.isEmpty)
    }

    @Test("argon2idDefault is RFC 9106 §4 second-option Argon2id")
    func argon2idDefaultParameters() {
        guard case let .argon2id(params, additional) = KDFParameters.argon2idDefault() else {
            Issue.record("Expected Argon2id")
            return
        }
        #expect(params.version == .v1_3)
        #expect(params.iterations == 3)
        #expect(params.memory == 64 * 1024 * 1024)
        #expect(params.parallelism == 4)
        #expect(params.salt.count == 32)
        #expect(additional.isEmpty)

        // Salt must be fresh on each call, never a fixed value.
        guard case let .argon2id(again, _) = KDFParameters.argon2idDefault() else {
            Issue.record("Expected Argon2id")
            return
        }
        #expect(again.salt != params.salt)
    }

    @Test("Defaults: 4.1 format, AES-256-CBC + gzip, ChaCha20 inner")
    func defaults() {
        let content = KDBXContent.makeEmpty(databaseName: "Defaults")
        #expect(content.header.formatVersion == .v4_1)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        // Argon2id by default.
        if case .argon2id = content.header.kdfParameters {} else {
            Issue.record("Expected Argon2id by default, got \(content.header.kdfParameters)")
        }
    }
}
