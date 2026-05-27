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
            maxArgon2Iterations: 1000,
            maxArgon2Parallelism: 1024,
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

    @Test("value exactly at the Argon2 memory limit does not breach")
    func atArgon2MemoryLimit_noBreach() {
        let limits = KDFParameterLimits.default
        #expect(limits.breach(for: argon2id(memory: limits.maxArgon2Memory)) == nil)
    }

    @Test("value exactly at the AES-KDF round limit does not breach")
    func atAESRoundLimit_noBreach() {
        let limits = KDFParameterLimits.default
        let params = KDFParameters.aes(.init(salt: Data(repeating: 0, count: 32), rounds: limits.maxAESKDFRounds), additional: [:])
        #expect(limits.breach(for: params) == nil)
    }

    @Test("default policy rejects a 16 GB memory bomb on the argon2d path")
    func defaultRejectsArgon2dMemoryBomb() {
        let params = KDFParameters.argon2d(
            .init(version: .v1_3, salt: Data(repeating: 0, count: 32), iterations: 1, memory: 16 * 1024 * 1024 * 1024, parallelism: 1),
            additional: [:]
        )
        #expect(KDFParameterLimits.default.breach(for: params) != nil)
    }

    @Test("computeUnlockKey rejects out-of-policy params before running the KDF")
    func computeUnlockKeyEnforces() throws {
        let unlock = UnlockData(masterPassword: "test")
        let bomb = argon2id(memory: 16 * 1024 * 1024 * 1024)
        do {
            _ = try unlock.computeUnlockKey(kdfParameters: bomb, limits: .default)
            Issue.record("Expected kdfParametersOutOfRange")
        } catch {
            guard case let .kdfParametersOutOfRange(reason) = error else {
                Issue.record("Expected kdfParametersOutOfRange, got \(error)")
                return
            }
            #expect(!reason.isEmpty)
        }
    }

    @Test("computeUnlockKey runs the KDF when params are within policy")
    func computeUnlockKeyProceeds() throws {
        let unlock = UnlockData(masterPassword: "test")
        // 8 MiB / 1 iteration is within .default and fast to compute.
        let small = argon2id(memory: 8 * 1024 * 1024, iterations: 1, parallelism: 1)
        let key = try unlock.computeUnlockKey(kdfParameters: small, limits: .default)
        #expect(key.count == 32)
    }

    @Test("parse() honors a tiny caller policy and rejects a real fixture's KDF")
    func parseHonorsTinyPolicy() throws {
        let url = try #require(Bundle.module.url(forResource: "simple-argon2id-aes256", withExtension: "kdbx"))
        let data = try Data(contentsOf: url)
        let tiny = KDFParameterLimits(
            maxArgon2Memory: 1024, // 1 KiB — below any real vault
            maxArgon2Iterations: 1,
            maxArgon2Parallelism: 1,
            maxAESKDFRounds: 1
        )
        do {
            // Wrong password on purpose: the KDF-limit check runs before HMAC
            // credential verification, so a tiny policy yields .kdfParametersOutOfRange
            // rather than .wrongCredentials. This pins that ordering.
            _ = try KDBXReader.parse(data, unlockData: UnlockData(masterPassword: "wrong"), kdfLimits: tiny)
            Issue.record("Expected kdfParametersOutOfRange")
        } catch {
            guard case .kdfParametersOutOfRange = error else {
                Issue.record("Expected kdfParametersOutOfRange, got \(error)")
                return
            }
        }
    }
}
