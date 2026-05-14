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
        let content = KDBXContent.makeEmpty(databaseName: "Test", kdf: .fast)
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

    @Test("Profiles produce different KDF parameters")
    func profilesDiffer() {
        let fast = KDFParameters.recommended(.fast)
        let balanced = KDFParameters.recommended(.balanced)
        let paranoid = KDFParameters.recommended(.paranoid)

        guard case let .argon2id(fastParams, _) = fast,
              case let .argon2id(balancedParams, _) = balanced,
              case let .argon2id(paranoidParams, _) = paranoid
        else {
            Issue.record("Expected Argon2id for all profiles")
            return
        }

        // Each profile must be strictly stronger than the previous.
        #expect(fastParams.iterations < balancedParams.iterations)
        #expect(balancedParams.iterations < paranoidParams.iterations)
        #expect(fastParams.memory < balancedParams.memory)
        #expect(balancedParams.memory < paranoidParams.memory)
    }

    @Test("Defaults: 4.1 format, AES-256-CBC + gzip, ChaCha20 inner")
    func defaults() {
        let content = KDBXContent.makeEmpty(databaseName: "Defaults", kdf: .fast)
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
