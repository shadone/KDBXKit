//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Caller-injected upper bounds on KDF cost. The KDF parameters in a KDBX
/// header are attacker-controlled; without a bound a crafted file can declare
/// multi-gigabyte Argon2 memory or billions of iterations and wedge or OOM the
/// host the moment an unlock is attempted. Callers pass the policy acceptable
/// for their device (e.g. a tighter memory ceiling on iPhone); ``default``
/// applies a generous-but-finite ceiling that real KeePass/KeePassXC vaults
/// never exceed.
///
/// Enforced at KDF execution only (``UnlockData/computeUnlockKey(kdfParameters:limits:)``
/// and the `KDBXReader.parse` paths), never in ``KDBXReader/parseHeader(_:)`` —
/// header inspection stays pure so a caller can read the parameters and warn
/// the user before attempting an expensive unlock.
public struct KDFParameterLimits: Sendable, Equatable {
    /// Maximum Argon2 memory cost, in bytes.
    public var maxArgon2Memory: UInt64
    /// Maximum Argon2 iteration (time) cost.
    public var maxArgon2Iterations: UInt64
    /// Maximum Argon2 parallelism (lanes).
    public var maxArgon2Parallelism: UInt32
    /// Maximum AES-KDF transform rounds. Pure CPU, so the ceiling is higher
    /// than the Argon2 iteration cap.
    public var maxAESKDFRounds: UInt64

    public init(
        maxArgon2Memory: UInt64,
        maxArgon2Iterations: UInt64,
        maxArgon2Parallelism: UInt32,
        maxAESKDFRounds: UInt64
    ) {
        self.maxArgon2Memory = maxArgon2Memory
        self.maxArgon2Iterations = maxArgon2Iterations
        self.maxArgon2Parallelism = maxArgon2Parallelism
        self.maxAESKDFRounds = maxAESKDFRounds
    }

    /// Generous defaults: real vaults sit far below these, absurd DoS values
    /// sit far above. KeePass Argon2 defaults are ~64 MiB / a few iterations.
    public static let `default` = KDFParameterLimits(
        maxArgon2Memory: 1 << 30, // 1 GiB
        maxArgon2Iterations: 1000,
        maxArgon2Parallelism: 1 << 10, // 1024 lanes
        maxAESKDFRounds: 100_000_000 // completes in a few seconds
    )

    /// Returns a human-readable reason when `params` exceed these limits, or
    /// `nil` when they are within policy. `.unknown` KDFs are not flagged here —
    /// they fail later as `unsupportedKDF`.
    public func breach(for params: KDFParameters) -> String? {
        switch params {
        case let .aes(p, _):
            if p.rounds > maxAESKDFRounds {
                return "AES-KDF rounds \(p.rounds) exceeds limit \(maxAESKDFRounds)"
            }
        case let .argon2d(p, _), let .argon2id(p, _):
            if p.memory > maxArgon2Memory {
                return "Argon2 memory \(p.memory) exceeds limit \(maxArgon2Memory)"
            }
            if p.iterations > maxArgon2Iterations {
                return "Argon2 iterations \(p.iterations) exceeds limit \(maxArgon2Iterations)"
            }
            if p.parallelism > maxArgon2Parallelism {
                return "Argon2 parallelism \(p.parallelism) exceeds limit \(maxArgon2Parallelism)"
            }
        case .unknown:
            break
        }
        return nil
    }
}
