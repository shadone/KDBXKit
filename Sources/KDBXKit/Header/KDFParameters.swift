//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Key derivation function parameters carried in the file header —
/// the algorithm choice plus the per-vault tuning that controls how
/// long an unlock takes.
///
/// On open the reader picks one of the four cases based on the KDF
/// UUID in the header; on save the writer serializes it back. The
/// `additional` `VariantDictionary` on each case preserves any
/// non-standard entries unknown to KDBXKit so a round-trip through
/// the library doesn't lose data plugins or other tools wrote.
///
/// For fresh vaults, prefer the standard default via
/// ``argon2idDefault()`` rather than constructing the cases directly,
/// or build an ``argon2id(_:additional:)`` value with parameters tuned
/// to your deployment. To upgrade a vault's KDF (legacy AES-KDF →
/// modern Argon2id) without breaking unlock with the same master
/// password, use ``KDBXContent/upgradeToArgon2id(to:)``.
public enum KDFParameters: Sendable, Equatable {
    /// AES-KDF parameters — legacy "AES iterated transform"
    /// KDF inherited from KeePass 1.x. Cryptographically much
    /// weaker than Argon2 against GPU/ASIC offline attackers; kept
    /// for compatibility with older files. New vaults should use
    /// Argon2id.
    public struct AES: Sendable, Equatable {
        /// Salt/seed (⟳).
        ///
        /// Value: `Byte[32]`
        public let salt: Data

        /// Number of AES iterations. Higher is slower (and stronger
        /// against offline attackers). KeePass 1.x defaults were
        /// 6000–60000; modern vaults that stick with AES-KDF
        /// typically use millions. Migrating to Argon2id (see
        /// ``KDFParameters/argon2id(_:additional:)``) is the better
        /// long-term answer.
        public let rounds: UInt64

        public init(salt: Data, rounds: UInt64) {
            self.salt = salt
            self.rounds = rounds
        }
    }

    /// Argon2 parameters (shared between argon2d and argon2id).
    ///
    /// Argon2 is the password-hashing-competition winner; it's
    /// memory-hard, which makes GPU/ASIC offline attacks expensive.
    /// Argon2id is the recommended variant for password hashing —
    /// argon2d is also defined here for compatibility with vaults
    /// that originally chose it.
    public struct Argon2: Sendable, Equatable {
        /// Argon2 algorithm version. 0x10 (1.0) or 0x13 (1.3).
        /// KDBXKit only supports 1.3 — 1.0 had a known bug and
        /// shouldn't be used.
        public enum Version: UInt32, CustomStringConvertible, Sendable {
            case v1_0 = 0x10
            case v1_3 = 0x13

            public var description: String {
                switch self {
                case .v1_0: return "1.0"
                case .v1_3: return "1.3"
                }
            }
        }

        /// Version. 0x10 (version 1.0) or 0x13 (version 1.3), as defined in the Argon2 specification. 0x13 is recommended.
        public let version: Version

        /// Salt (⟳).
        ///
        /// Size: minimum 8, maximum 0x3FFFFFFF, recommended 32.
        ///
        /// - note: Must be regenerated each time KDBX file is saved!
        public let salt: Data

        /// Iterations.
        ///
        /// Minimum 1, maximum 0xFFFFFFFF.
        public let iterations: UInt64

        /// Memory, in bytes.
        ///
        /// Minimum 8192, maximum 0x7FFFFFFF.
        public let memory: UInt64

        /// Parallelism.
        ///
        /// Minimum 1, maximum 0x00FFFFFF.
        public let parallelism: UInt32

        public init(
            version: Version,
            salt: Data,
            iterations: UInt64,
            memory: UInt64,
            parallelism: UInt32
        ) {
            self.version = version
            self.salt = salt
            self.iterations = iterations
            self.memory = memory
            self.parallelism = parallelism
        }
    }

    /// AES iterated KDF — the KeePass 1.x / early KDBX 4 default.
    /// `additional` preserves any vendor-specific entries from the
    /// header's KDF variant dictionary that KDBXKit doesn't model.
    case aes(AES, additional: VariantDictionary)

    /// Argon2 in **data-dependent** mode. Stronger than AES-KDF
    /// against GPU offline attacks; weaker than Argon2id against
    /// side-channel attacks. Kept for compatibility with files that
    /// originally chose this variant.
    case argon2d(Argon2, additional: VariantDictionary)

    /// Argon2 in **hybrid (id)** mode — the recommended choice for
    /// password hashing and the default for new vaults KDBXKit
    /// creates via ``argon2idDefault()`` / ``KDBXContent/makeEmpty(databaseName:kdf:generator:)``.
    case argon2id(Argon2, additional: VariantDictionary)

    /// A KDF whose UUID isn't one KDBXKit implements. The reader
    /// emits this case when it parses a header with an unknown KDF
    /// UUID; attempting to unlock such a file throws
    /// ``UnlockDataError/unsupportedKDF(_:)``. The writer rejects
    /// `.unknown` outright — there's no path through which a vault
    /// with an unsupported KDF can be saved.
    case unknown(uuid: UUID)

    /// Compact one-line summary for perf/timing logs, e.g.
    /// `argon2d m=65536KiB t=151 p=12`. Not localized; diagnostics only.
    var perfSummary: String {
        switch self {
        case let .aes(aes, _):
            return "aes-kdf rounds=\(aes.rounds)"
        case let .argon2d(a, _):
            return "argon2d m=\(a.memory / 1024)KiB t=\(a.iterations) p=\(a.parallelism)"
        case let .argon2id(a, _):
            return "argon2id m=\(a.memory / 1024)KiB t=\(a.iterations) p=\(a.parallelism)"
        case let .unknown(uuid):
            return "unknown-kdf \(uuid)"
        }
    }

    var aes: (params: AES, additional: VariantDictionary)? {
        guard case let .aes(aes, additional) = self else { return nil }
        return (aes, additional)
    }

    var argon2d: (params: Argon2, additional: VariantDictionary)? {
        guard case let .argon2d(argon2, additional) = self else { return nil }
        return (argon2, additional)
    }

    var argon2id: (params: Argon2, additional: VariantDictionary)? {
        guard case let .argon2id(argon2, additional) = self else { return nil }
        return (argon2, additional)
    }

    var unknown: UUID? {
        guard case let .unknown(uuid) = self else { return nil }
        return uuid
    }
}

extension KDFParameters {
    enum KDF {
        static let AES = UUID(uuid: (0xEA, 0x4F, 0x8A, 0xC1, 0x08, 0x0D, 0x74, 0xBF, 0x60, 0x44, 0x8A, 0x62, 0x9A, 0xF3, 0xD9, 0xC9))
        static let Argon2d = UUID(uuid: (0x0C, 0x0A, 0xE3, 0x03, 0xA4, 0xA9, 0xF7, 0x91, 0x4B, 0x44, 0x29, 0x8C, 0xDF, 0x6D, 0x63, 0xEF))
        static let Argon2id = UUID(uuid: (0xE6, 0xA1, 0xF0, 0xC6, 0x3E, 0xFC, 0x3D, 0xB2, 0x73, 0x47, 0xDB, 0x56, 0x19, 0x8B, 0x29, 0x9E))
    }

    init?(from params: VariantDictionary) {
        guard case let .bytes(uuidData) = params["$UUID"] else {
            KDBXLog.kdf.debug("KDF Parameters: Missing required '$UUID' key")
            return nil
        }
        guard let uuid = uuidData.asUUIDLE() else {
            KDBXLog.kdf.debug("KDF Parameters: Invalid '$UUID' key length (expected 16, got \(uuidData.count): \(uuidData.hexString)")
            return nil
        }

        if uuid == KDF.AES {
            guard
                case let .bytes(salt) = params["S"],
                case let .uint64(rounds) = params["R"]
            else {
                return nil
            }

            // The AES-KDF transform seed is exactly 32 bytes (the 3.x route
            // validates its TransformSeed the same way). AESKDF.derive
            // preconditions on this, and the unlock key is computed before
            // the header HMAC check — rejecting here keeps a crafted header
            // a typed parse error instead of a pre-auth process abort.
            guard salt.count == 32 else {
                KDBXLog.kdf.debug("KDF Parameters: Invalid AES-KDF salt length (expected 32, got \(salt.count))")
                return nil
            }

            var additionalParams = params
            additionalParams.removeValue(forKey: "$UUID")
            additionalParams.removeValue(forKey: "S")
            additionalParams.removeValue(forKey: "R")

            self = .aes(.init(salt: salt, rounds: rounds), additional: additionalParams)
        } else if uuid == KDF.Argon2d || uuid == KDF.Argon2id {
            guard
                case let .uint32(versionRawValue) = params["V"],
                case let .bytes(salt) = params["S"],
                case let .uint64(iterations) = params["I"],
                case let .uint64(memory) = params["M"],
                case let .uint32(parallelism) = params["P"]
            else {
                return nil
            }

            guard let version = Argon2.Version(rawValue: versionRawValue) else {
                KDBXLog.kdf.debug("KDF Parameters: Unsupported version of Argon2: \(versionRawValue)")
                return nil
            }

            if case .v1_0 = version {
                KDBXLog.kdf.debug("KDF Parameters: Argon2 version 1.0 is not supported: \(versionRawValue)")
                return nil
            }

            var additionalParams = params
            additionalParams.removeValue(forKey: "$UUID")
            additionalParams.removeValue(forKey: "V")
            additionalParams.removeValue(forKey: "S")
            additionalParams.removeValue(forKey: "I")
            additionalParams.removeValue(forKey: "M")
            additionalParams.removeValue(forKey: "P")

            let params = Argon2(
                version: version,
                salt: salt,
                iterations: iterations,
                memory: memory,
                parallelism: parallelism
            )
            if uuid == KDF.Argon2d {
                self = .argon2d(params, additional: additionalParams)
            } else {
                self = .argon2id(params, additional: additionalParams)
            }
        } else {
            self = .unknown(uuid: uuid)
        }
    }

    func toVariantDictionary() -> VariantDictionary {
        var result: VariantDictionary = [:]

        switch self {
        case let .aes(aes, additional):
            result = additional

            result["$UUID"] = .bytes(KDF.AES.toUInt128().toDataLittleEndian())
            result["S"] = .bytes(aes.salt)
            result["R"] = .uint64(aes.rounds)

        case let .argon2d(params, additional):
            result = additional

            result["$UUID"] = .bytes(KDF.Argon2d.toUInt128().toDataLittleEndian())
            result["V"] = .uint32(params.version.rawValue)
            result["S"] = .bytes(params.salt)
            result["I"] = .uint64(params.iterations)
            result["M"] = .uint64(params.memory)
            result["P"] = .uint32(params.parallelism)

        case let .argon2id(params, additional):
            result = additional

            result["$UUID"] = .bytes(KDF.Argon2id.toUInt128().toDataLittleEndian())
            result["V"] = .uint32(params.version.rawValue)
            result["S"] = .bytes(params.salt)
            result["I"] = .uint64(params.iterations)
            result["M"] = .uint64(params.memory)
            result["P"] = .uint32(params.parallelism)

        case let .unknown(uuid):
            // Reachable only from programmer error — `KDFParameters.unknown`
            // is constructed by the reader for KDFs we don't implement; if
            // such a value reaches the writer, something upstream broke the
            // "writer rejects unsupported KDFs at the parse->write boundary"
            // invariant. Not from adversarial input.
            fatalError("Writing unsupported KDF Parameters is not implemented: \(uuid.uuidString)")
        }

        return result
    }
}
