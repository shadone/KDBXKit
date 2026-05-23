//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("UnlockData — rehydration from raw key data")
struct UnlockDataTests {
    @Test("rawKeyData init produces an UnlockData with the same key bytes")
    func rawKeyDataRoundtrip() {
        let bytes = Data((0..<32).map { UInt8($0) })
        let unlock = UnlockData(rawKeyData: bytes)
        let roundtripped = unlock.keyDataBytes.withUnsafeBytes { Data($0) }
        #expect(roundtripped == bytes)
    }

    @Test("rawKeyData unlock decrypts a vault created with the matching password")
    func rawKeyDataUnlocksRealVault() throws {
        // The pre-hash R = SHA-256( SHA-256(password.utf8) ). Recompute and
        // confirm a vault built with the password opens identically when
        // we rehydrate the UnlockData from those 32 bytes only.
        let password = "correct horse battery staple"
        let preHash = password.data(using: .utf8)!.sha256().sha256()

        let viaPassword = UnlockData(masterPassword: password)
        let viaRaw = UnlockData(rawKeyData: preHash)

        let bytesA = viaPassword.keyDataBytes.withUnsafeBytes { Data($0) }
        let bytesB = viaRaw.keyDataBytes.withUnsafeBytes { Data($0) }
        #expect(bytesA == bytesB)
    }

    @Test("matches() returns true for the same password, false otherwise")
    func matchesSamePassword() {
        let unlock = UnlockData(masterPassword: "the right password")
        #expect(unlock.matches(UnlockData(masterPassword: "the right password")) == true)
        #expect(unlock.matches(UnlockData(masterPassword: "the wrong password")) == false)
    }

    /// Argon2 KDFParameters that carry a non-empty secret key `K` or
    /// associated data `A` are explicitly rejected. We call the raw
    /// Argon2 hash entry points which don't accept those inputs;
    /// silently deriving a wrong key would surface as "wrong password"
    /// and obscure the real reason.
    @Test("computeUnlockKey rejects Argon2 KDFParameters with non-empty K or A")
    func argon2idWithSecretKeyIsRejected() throws {
        let params = KDFParameters.Argon2(
            version: .v1_3,
            salt: Data(repeating: 0x01, count: 32),
            iterations: 1,
            memory: 8 * 1024 * 1024,
            parallelism: 1
        )
        let withK: VariantDictionary = ["K": .bytes(Data([0xAA, 0xBB, 0xCC]))]
        let withA: VariantDictionary = ["A": .bytes(Data([0xDD]))]

        let unlock = UnlockData(masterPassword: "any")

        #expect(throws: UnlockDataError.unsupportedKDFParameter(name: "K")) {
            try unlock.computeUnlockKey(kdfParameters: .argon2id(params, additional: withK))
        }
        #expect(throws: UnlockDataError.unsupportedKDFParameter(name: "A")) {
            try unlock.computeUnlockKey(kdfParameters: .argon2d(params, additional: withA))
        }
    }

    /// An empty K or A entry (a present-but-zero-length byte array) is
    /// semantically identical to omitting the parameter and MUST NOT
    /// trip the rejection path.
    @Test("computeUnlockKey accepts Argon2 KDFParameters with empty K or A")
    func argon2idWithEmptyKAndAIsAccepted() throws {
        let params = KDFParameters.Argon2(
            version: .v1_3,
            salt: Data(repeating: 0x02, count: 32),
            iterations: 1,
            memory: 8 * 1024 * 1024,
            parallelism: 1
        )
        let emptyExtras: VariantDictionary = [
            "K": .bytes(Data()),
            "A": .bytes(Data()),
        ]

        let unlock = UnlockData(masterPassword: "any")
        // Should not throw the unsupportedKDFParameter case. If Argon2
        // itself fails (it shouldn't for these parameters), that's a
        // different error class.
        _ = try unlock.computeUnlockKey(kdfParameters: .argon2id(params, additional: emptyExtras))
    }
}
