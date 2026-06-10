//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

// Backwards-compatibility shims.
//
// KDBXKit 1.3.0 moved KDF cost-tier policy out of the library: how many
// tiers to expose, what to call them, and how to tune them against a
// device or runtime is application policy, not a general-purpose library
// concern (see ``KDFParameters/argon2idDefault()``). The pre-tuned
// fast / balanced / paranoid profiles below are kept — unchanged — so
// existing callers keep compiling and producing identical parameters,
// but they are deprecated in favour of the portable default or an
// explicitly-constructed ``KDFParameters/argon2id(_:additional:)`` value.
public extension KDFParameters {
    /// Pre-tuned Argon2id cost tiers for new vaults.
    ///
    /// - Note: Deprecated in 1.3.0. Cost-tier taxonomy is application
    ///   policy; the library ships only a single portable default. Use
    ///   ``KDFParameters/argon2idDefault()`` or construct an
    ///   ``KDFParameters/argon2id(_:additional:)`` value tuned to your
    ///   deployment instead.
    @available(*, deprecated, message: "KDF cost tiers are application policy. Use KDFParameters.argon2idDefault() for a portable default, or construct argon2id(_:additional:) with parameters tuned to your deployment.")
    enum Profile: Sendable, Equatable {
        /// ≈ 100 ms KDF on contemporary Apple Silicon: Argon2id t=8,
        /// m=64 MiB, p=4.
        case fast
        /// ≈ 300 ms KDF on contemporary Apple Silicon: Argon2id t=24,
        /// m=64 MiB, p=4.
        case balanced
        /// ≈ 900 ms KDF on contemporary Apple Silicon: Argon2id t=40,
        /// m=128 MiB, p=4.
        case paranoid
    }

    /// Build a fresh `KDFParameters` value for one of the standard
    /// profiles. Argon2id v1.3 with a 32-byte random salt.
    ///
    /// - Note: Deprecated in 1.3.0. See ``Profile``.
    @available(*, deprecated, message: "KDF cost tiers are application policy. Use KDFParameters.argon2idDefault() for a portable default, or construct argon2id(_:additional:) with parameters tuned to your deployment.")
    static func recommended(_ profile: Profile) -> KDFParameters {
        let salt = SecureRandom.bytes(32)
        switch profile {
        case .fast:
            return .argon2id(
                .init(version: .v1_3, salt: salt, iterations: 8, memory: 64 * 1024 * 1024, parallelism: 4),
                additional: [:]
            )
        case .balanced:
            return .argon2id(
                .init(version: .v1_3, salt: salt, iterations: 24, memory: 64 * 1024 * 1024, parallelism: 4),
                additional: [:]
            )
        case .paranoid:
            return .argon2id(
                .init(version: .v1_3, salt: salt, iterations: 40, memory: 128 * 1024 * 1024, parallelism: 4),
                additional: [:]
            )
        }
    }
}
