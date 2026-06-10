//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// 1.3.0 deprecated, but did not remove, the pre-tuned KDF profiles.
/// These tests pin the backwards-compatibility contract: the deprecated
/// `Profile` / `recommended(_:)` API and the deprecated `Profile`-taking
/// overloads of `makeEmpty` / `upgradeToArgon2id` keep compiling and
/// keep producing the exact same parameters they did before.
///
/// This file intentionally exercises deprecated API, so the build emits
/// deprecation warnings here by design.
@Suite("KDF profile backwards-compatibility")
struct KDFProfileCompatTests {

    @Test("recommended(.fast) is unchanged: Argon2id t=8, m=64 MiB, p=4")
    func fastUnchanged() {
        guard case let .argon2id(p, _) = KDFParameters.recommended(.fast) else {
            Issue.record("Expected Argon2id"); return
        }
        #expect(p.version == .v1_3)
        #expect(p.iterations == 8)
        #expect(p.memory == 64 * 1024 * 1024)
        #expect(p.parallelism == 4)
        #expect(p.salt.count == 32)
    }

    @Test("recommended(.balanced) is unchanged: Argon2id t=24, m=64 MiB, p=4")
    func balancedUnchanged() {
        guard case let .argon2id(p, _) = KDFParameters.recommended(.balanced) else {
            Issue.record("Expected Argon2id"); return
        }
        #expect(p.iterations == 24)
        #expect(p.memory == 64 * 1024 * 1024)
        #expect(p.parallelism == 4)
    }

    @Test("recommended(.paranoid) is unchanged: Argon2id t=40, m=128 MiB, p=4")
    func paranoidUnchanged() {
        guard case let .argon2id(p, _) = KDFParameters.recommended(.paranoid) else {
            Issue.record("Expected Argon2id"); return
        }
        #expect(p.iterations == 40)
        #expect(p.memory == 128 * 1024 * 1024)
        #expect(p.parallelism == 4)
    }

    @Test("makeEmpty(kdf: Profile) overload still builds a vault with that profile's KDF")
    func makeEmptyProfileOverload() {
        let content = KDBXContent.makeEmpty(databaseName: "Compat", kdf: .paranoid)
        guard case let .argon2id(p, _) = content.header.kdfParameters else {
            Issue.record("Expected Argon2id"); return
        }
        #expect(p.iterations == 40)
        #expect(p.memory == 128 * 1024 * 1024)
    }

    @Test("upgradeToArgon2id(profile:) overload upgrades to that profile's KDF")
    func upgradeProfileOverload() {
        // Start from an AES-KDF vault, then upgrade via the deprecated path.
        var content = KDBXContent.makeEmpty(
            databaseName: "Legacy",
            kdf: .argon2id(.init(version: .v1_3, salt: SecureRandom.bytes(32),
                                 iterations: 2, memory: 8 * 1024 * 1024, parallelism: 1),
                           additional: [:])
        )
        content.upgradeToArgon2id(profile: .balanced)
        guard case let .argon2id(p, _) = content.header.kdfParameters else {
            Issue.record("Expected Argon2id"); return
        }
        #expect(p.iterations == 24)
        #expect(p.memory == 64 * 1024 * 1024)
    }
}
