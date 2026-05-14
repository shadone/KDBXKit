//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDFParameters {
    /// Pre-tuned Argon2id profiles for new vaults. The numbers below are
    /// approximate; the actual unlock time depends on the hardware running
    /// the KDF (faster on M-series Macs, slower on older iPhones).
    enum Profile: Sendable, Equatable {
        /// ≈ 500 ms KDF on contemporary Apple Silicon. Suitable for vaults
        /// that are unlocked often (menubar popover) or hold lower-value
        /// secrets. Still resistant to casual attackers; weaker against
        /// determined attackers with custom hardware.
        case fast

        /// ≈ 1.5 s KDF — matches modern KeePass / KeePassXC defaults.
        /// Recommended for most users.
        case balanced

        /// ≈ 4 s KDF. Strong against dedicated offline attackers. Choose
        /// for vaults whose contents are exceptionally valuable and where
        /// unlock latency is acceptable.
        case paranoid
    }

    /// Build a fresh `KDFParameters` value for one of the standard profiles.
    /// Uses Argon2id v1.3 with a 32-byte random salt.
    static func recommended(_ profile: Profile) -> KDFParameters {
        let salt = SecureRandom.bytes(32)
        switch profile {
        case .fast:
            return .argon2id(
                .init(version: .v1_3, salt: salt, iterations: 2, memory: 32 * 1024 * 1024, parallelism: 4),
                additional: [:]
            )
        case .balanced:
            return .argon2id(
                .init(version: .v1_3, salt: salt, iterations: 5, memory: 64 * 1024 * 1024, parallelism: 4),
                additional: [:]
            )
        case .paranoid:
            return .argon2id(
                .init(version: .v1_3, salt: salt, iterations: 20, memory: 256 * 1024 * 1024, parallelism: 4),
                additional: [:]
            )
        }
    }
}
