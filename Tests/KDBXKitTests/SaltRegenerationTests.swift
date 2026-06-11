//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("Salt regeneration on write")
struct SaltRegenerationTests {
    /// The KDBX spec requires masterSalt, encryptionNonce, and the KDF salt
    /// to be fresh on every save. By default `KDBXWriter.write` regenerates
    /// them, so two saves of the same content produce byte-different files.
    @Test
    func defaultsToRegenerating() throws {
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let referenceData = try Data(contentsOf: URL(filePath: kdbxFilepath))

        let unlock = UnlockData(masterPassword: "123")
        var reader = KDBXReader(referenceData)
        let content = try reader.parse(unlockData: unlock)

        let firstWrite = try writeToMemory(content, unlockData: unlock)
        let secondWrite = try writeToMemory(content, unlockData: unlock)

        // Same content + same password — different ciphertext, because
        // both writes pulled fresh random salts.
        #expect(firstWrite != secondWrite)

        // But each must still decrypt back to the original content.
        var firstReader = KDBXReader(firstWrite)
        let firstParsed = try firstReader.parse(unlockData: unlock)
        var secondReader = KDBXReader(secondWrite)
        let secondParsed = try secondReader.parse(unlockData: unlock)

        #expect(firstParsed.database == content.database)
        #expect(secondParsed.database == content.database)

        // And critically: the headers should differ in their random salts
        // between the two writes.
        #expect(firstParsed.header.masterSalt != secondParsed.header.masterSalt)
        #expect(firstParsed.header.encryptionNonce != secondParsed.header.encryptionNonce)
    }

    /// The inner random-stream key must be fresh on every save too —
    /// KeePass and KeePassXC regenerate it per write, and the writer's
    /// re-encryption of protected values assumes it (lazyInnerCipher
    /// values decrypt with the reader's keystream and re-encrypt with
    /// the writer's).
    @Test
    func regeneratesInnerStreamKey() throws {
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let referenceData = try Data(contentsOf: URL(filePath: kdbxFilepath))

        let unlock = UnlockData(masterPassword: "123")
        var reader = KDBXReader(referenceData)
        let content = try reader.parse(unlockData: unlock)

        let firstWrite = try writeToMemory(content, unlockData: unlock)
        let secondWrite = try writeToMemory(content, unlockData: unlock)

        var firstReader = KDBXReader(firstWrite)
        let firstParsed = try firstReader.parse(unlockData: unlock)
        var secondReader = KDBXReader(secondWrite)
        let secondParsed = try secondReader.parse(unlockData: unlock)

        // Fresh inner key on each save — different from the source file
        // and from each other.
        #expect(firstParsed.innerHeader.encryptionKey != content.innerHeader.encryptionKey)
        #expect(firstParsed.innerHeader.encryptionKey != secondParsed.innerHeader.encryptionKey)

        // And the protected values still decrypt to the same content.
        #expect(firstParsed.database == content.database)
        #expect(secondParsed.database == content.database)
    }

    /// `regenerateSalts: false` is the round-trip escape hatch: two writes
    /// of the same content produce identical bytes.
    @Test
    func optingOutPreservesSalts() throws {
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let referenceData = try Data(contentsOf: URL(filePath: kdbxFilepath))

        let unlock = UnlockData(masterPassword: "123")
        var reader = KDBXReader(referenceData)
        let content = try reader.parse(unlockData: unlock)

        let firstWrite = try writeToMemory(content, unlockData: unlock, regenerateSalts: false)
        let secondWrite = try writeToMemory(content, unlockData: unlock, regenerateSalts: false)

        #expect(firstWrite == secondWrite)
    }

    // MARK: - Helper

    private func writeToMemory(
        _ content: KDBXContent,
        unlockData: UnlockData,
        regenerateSalts: Bool = true
    ) throws -> Data {
        let stream = OutputStream(toMemory: ())
        stream.open()
        defer { stream.close() }
        try KDBXWriter(to: stream).write(content, unlockData: unlockData, regenerateSalts: regenerateSalts)
        return stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
    }
}
