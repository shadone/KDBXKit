//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDFParameters {
    /// A sane, modern default for new vaults: Argon2id v1.3 with a
    /// fresh 32-byte random salt.
    ///
    /// The cost parameters follow the second recommended option in
    /// RFC 9106 §4 ("Parameter Choice") — `t=3`, `m=64 MiB`, `p=4` —
    /// the memory-constrained recommendation intended for
    /// general-purpose use, and consistent with the OWASP Password
    /// Storage Cheat Sheet's Argon2id guidance.
    ///
    /// This is deliberately a single, portable, hardware-neutral
    /// default. KDBXKit does not ship a tiered "fast / balanced /
    /// paranoid" taxonomy: how many cost tiers to expose, what to call
    /// them, and how to tune them against a particular device or
    /// runtime (UI unlock latency, an embedded memory ceiling, the
    /// slowest device a synced vault must open on) are application
    /// policy. Apps with those constraints should construct
    /// ``KDFParameters/argon2id(_:additional:)`` directly with values
    /// tuned to their own deployment rather than relying on this.
    ///
    /// RFC 9106 §4: https://www.rfc-editor.org/rfc/rfc9106.html#section-4
    static func argon2idDefault() -> KDFParameters {
        .argon2id(
            .init(
                version: .v1_3,
                salt: SecureRandom.bytes(32),
                iterations: 3,
                memory: 64 * 1024 * 1024,
                parallelism: 4
            ),
            additional: [:]
        )
    }
}
