//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

/// Named Argon2id cost tiers offered by the `kdbx` CLI's `create`,
/// `set-kdf`, and `migrate` commands.
///
/// These are the CLI's own policy, not the library's. KDBXKit exposes
/// only a single portable default (``KDFParameters/argon2idDefault()``);
/// deciding how many tiers to surface and how to tune them is an
/// application concern. The `kdbx` CLI is a desktop / server tool with
/// no fixed memory ceiling, so it can afford more memory at the high
/// end than a memory-constrained mobile host would.
///
/// All tiers use Argon2id v1.3, `p=4`, and a fresh 32-byte random salt.
/// Numbers are anchored to RFC 9106 §4 and the OWASP Password Storage
/// Cheat Sheet:
/// - `balanced` is the RFC 9106 second recommended option (`t=3`,
///   `m=64 MiB`) — the same value as ``KDFParameters/argon2idDefault()``.
/// - `fast` trades iterations for snappier unlock.
/// - `paranoid` raises both memory and iterations for high-value vaults.
enum KDFProfile: String, ExpressibleByArgument, CaseIterable {
    case fast
    case balanced
    case paranoid

    /// Fresh ``KDFParameters`` for this tier, with a new random salt.
    var kdfParameters: KDFParameters {
        switch self {
        case .fast:
            return .argon2id(argon2(iterations: 2, memoryMiB: 64), additional: [:])
        case .balanced:
            return .argon2id(argon2(iterations: 3, memoryMiB: 64), additional: [:])
        case .paranoid:
            return .argon2id(argon2(iterations: 8, memoryMiB: 256), additional: [:])
        }
    }

    private func argon2(iterations: UInt64, memoryMiB: UInt64) -> KDFParameters.Argon2 {
        .init(
            version: .v1_3,
            salt: Self.randomSalt(32),
            iterations: iterations,
            memory: memoryMiB * 1024 * 1024,
            parallelism: 4
        )
    }

    /// CSPRNG salt. Mirrors KDBXKit's `SecureRandom` (which is
    /// internal to the library): Swift's `SystemRandomNumberGenerator`
    /// wraps `arc4random_buf` on Apple and `getrandom(2)` on Linux. The
    /// writer regenerates salts on save anyway, so this value is
    /// transient, but it is still drawn from a cryptographic source.
    private static func randomSalt(_ length: Int) -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<length).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }
}
