//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDFParameterLimits — caller-injected KDF cost policy")
struct KDFParameterLimitsTests {
    private func argon2id(memory: UInt64, iterations: UInt64 = 1, parallelism: UInt32 = 1) -> KDFParameters {
        .argon2id(
            .init(version: .v1_3, salt: Data(repeating: 0, count: 32), iterations: iterations, memory: memory, parallelism: parallelism),
            additional: [:]
        )
    }

    @Test("default policy admits a normal vault (64 MiB Argon2)")
    func defaultAdmitsNormal() {
        #expect(KDFParameterLimits.default.breach(for: argon2id(memory: 64 * 1024 * 1024)) == nil)
    }

    @Test("default policy rejects a 16 GB memory bomb")
    func defaultRejectsMemoryBomb() {
        #expect(KDFParameterLimits.default.breach(for: argon2id(memory: 16 * 1024 * 1024 * 1024)) != nil)
    }

    @Test("a permissive custom policy admits the same large value")
    func permissivePolicyAdmits() {
        let permissive = KDFParameterLimits(
            maxArgon2Memory: 32 * 1024 * 1024 * 1024,
            maxArgon2Iterations: 1_000,
            maxArgon2Parallelism: 1_024,
            maxAESKDFRounds: 1_000_000_000
        )
        #expect(permissive.breach(for: argon2id(memory: 16 * 1024 * 1024 * 1024)) == nil)
    }

    @Test("AES-KDF round bomb is rejected by default")
    func defaultRejectsAESRoundBomb() {
        let params = KDFParameters.aes(.init(salt: Data(repeating: 0, count: 32), rounds: .max), additional: [:])
        #expect(KDFParameterLimits.default.breach(for: params) != nil)
    }

    @Test("unknown KDF is not flagged by the limit check")
    func unknownKDFNotFlagged() {
        #expect(KDFParameterLimits.default.breach(for: .unknown(uuid: UUID())) == nil)
    }
}
