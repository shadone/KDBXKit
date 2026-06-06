//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDFParameters {
    /// Pre-tuned Argon2id profiles for new vaults. Times below were
    /// measured in Release on contemporary Apple Silicon (M-series);
    /// the oldest supported iPhones (A12-class) run the same KDF roughly
    /// 3-4x slower, and that slower device — not the Mac — is the anchor
    /// each profile is tuned against, because a synced vault unlocks on
    /// every family device.
    enum Profile: Sendable, Equatable {
        /// ≈ 100 ms KDF on contemporary Apple Silicon (≈ 0.3-0.4 s on
        /// A12-class iPhones). Suitable for vaults that are unlocked
        /// often (menubar popover) or hold lower-value secrets. Still
        /// resistant to casual attackers; weaker against determined
        /// attackers with custom hardware.
        case fast

        /// ≈ 300 ms KDF on contemporary Apple Silicon (≈ 1 s on A12-class
        /// iPhones) — the "about a second on typical hardware" anchor
        /// KeePassXC's benchmark targets, where typical hardware for a
        /// synced vault is the slowest phone that opens it. Recommended
        /// for most users.
        case balanced

        /// ≈ 900 ms KDF on contemporary Apple Silicon (≈ 3-4 s on
        /// A12-class iPhones). Strong against dedicated offline attackers.
        /// Choose for vaults whose contents are exceptionally valuable and
        /// where unlock latency is acceptable.
        case paranoid
    }

    /// Build a fresh `KDFParameters` value for one of the standard profiles.
    /// Uses Argon2id v1.3 with a 32-byte random salt.
    ///
    /// Memory is capped at 128 MiB across all profiles: the iOS AutoFill
    /// extension unlocks vaults under a tight (~120 MB) jetsam limit, and
    /// Argon2 allocates its full working set up front — so the cost
    /// headroom above `.fast` comes primarily from iterations, not memory.
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
