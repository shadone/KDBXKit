//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// KDF behavior across a 3.x → 4.1 migration: what the library does
/// by default, and the opt-in `upgradeKDF` / `upgradeToArgon2id` API
/// callers reach for when "as written" isn't appropriate (Passie wants
/// to upgrade 3.x AES-KDF vaults to Argon2id on first save).
@Suite("KDF migration on save")
struct KDFMigrationTests {

    /// Stock kpxc-kdbx31-default — KDBX 3.1 (AES-KDF only). The
    /// migration scenarios all start here.
    private static func opened3xVault() throws -> KDBXContent {
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        return try KDBXReader.parse(data, unlockData: .init(masterPassword: "test"))
    }

    private static func roundTrip(_ content: KDBXContent, password: String) throws -> KDBXContent {
        let output = OutputStream.toMemory()
        output.open()
        let writer = KDBXWriter(to: output)
        try writer.write(content, unlockData: .init(masterPassword: password))
        output.close()
        let bytes = output.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        return try KDBXReader.parse(bytes, unlockData: .init(masterPassword: password))
    }

    @Test("Default migration preserves AES-KDF (smallest, most reversible diff)")
    func defaultMigration_preservesAES_KDF() throws {
        let original = try Self.opened3xVault()
        let originalAES = try #require(original.header.kdfParameters.aes)

        let migrated = try Self.roundTrip(original, password: "test")

        // Format upgraded to 4.1 (writer clamp), KDF identity
        // preserved — Argon2id is not selected behind the user's
        // back. Salt is regenerated on save per spec; rounds stay
        // the same.
        #expect(migrated.header.formatVersion == .v4_1)
        let migratedAES = try #require(migrated.header.kdfParameters.aes)
        #expect(migratedAES.params.rounds == originalAES.params.rounds)
        #expect(migratedAES.params.salt != originalAES.params.salt, "salt must regenerate on save")
        #expect(migratedAES.params.salt.count == originalAES.params.salt.count)
    }

    @Test("upgradeToArgon2id swaps AES-KDF for Argon2id; same master password unlocks the result")
    func upgradeToArgon2id_swapsKDFAndUnlockSucceeds() throws {
        var content = try Self.opened3xVault()
        #expect(content.header.kdfParameters.aes != nil, "fixture sanity: starts on AES-KDF")

        content.upgradeToArgon2id()

        // Header reflects the upgrade immediately (pure mutation).
        // The writer hasn't run yet so the on-disk file is still 3.1
        // — the in-memory header is what the next save will emit.
        #expect(content.header.kdfParameters.argon2id != nil)
        #expect(content.header.kdfParameters.aes == nil)

        // Round-trip with the same password the original vault used.
        // The writer derives a new unlock key from the new KDF; the
        // user types the same password.
        let reopened = try Self.roundTrip(content, password: "test")
        #expect(reopened.header.formatVersion == .v4_1)
        #expect(reopened.header.kdfParameters.argon2id != nil)

        // Vault contents survive the KDF swap — sanity that we
        // didn't accidentally re-encrypt anything with stale keys.
        let originalEntry = try #require(content.database.root.group.entries.first)
        let reopenedEntry = try #require(reopened.database.root.group.entries.first)
        #expect(originalEntry.uuid == reopenedEntry.uuid)
        let password = try #require(reopenedEntry.strings.first(where: { $0.key == "Password" }))
        #expect(password.value.bytes.withRevealedString { $0 } == "secret123")
    }

    @Test("upgradeToArgon2id picks the requested profile")
    func upgradeToArgon2id_honorsProfile() throws {
        var fast = try Self.opened3xVault()
        var balanced = try Self.opened3xVault()
        var paranoid = try Self.opened3xVault()

        fast.upgradeToArgon2id(profile: .fast)
        balanced.upgradeToArgon2id(profile: .balanced)
        paranoid.upgradeToArgon2id(profile: .paranoid)

        let fastParams = try #require(fast.header.kdfParameters.argon2id).params
        let balancedParams = try #require(balanced.header.kdfParameters.argon2id).params
        let paranoidParams = try #require(paranoid.header.kdfParameters.argon2id).params

        // Profiles encode increasing iteration / memory cost. The
        // exact numbers live in KDFParameters.recommended(_:) and
        // can shift over time as hardware speeds up — assert the
        // ordering rather than literal values.
        #expect(fastParams.iterations <= balancedParams.iterations)
        #expect(balancedParams.iterations <= paranoidParams.iterations)
        #expect(fastParams.memory <= balancedParams.memory)
        #expect(balancedParams.memory <= paranoidParams.memory)
    }

    @Test("upgradeKDF is general — accepts any KDFParameters")
    func upgradeKDF_acceptsArbitraryParameters() throws {
        var content = try Self.opened3xVault()

        // Build a deliberately unusual KDF — explicit AES-KDF with a
        // higher round count than the source — to exercise the
        // general API. Production callers will typically reach for
        // upgradeToArgon2id, but the lower-level API exists for cases
        // where the caller wants exact control over parameters.
        let customKDF: KDFParameters = .aes(
            .init(salt: Data(repeating: 0xAA, count: 32), rounds: 5_000_000),
            additional: [:]
        )
        content.upgradeKDF(to: customKDF)

        let upgraded = try #require(content.header.kdfParameters.aes)
        #expect(upgraded.params.rounds == 5_000_000)

        // Survives a write-cycle.
        let reopened = try Self.roundTrip(content, password: "test")
        let reopenedAES = try #require(reopened.header.kdfParameters.aes)
        #expect(reopenedAES.params.rounds == 5_000_000)
    }
}
