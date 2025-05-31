//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDFParameters {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        switch self {
        case let .aes(params, additional):
            if !additional.isEmpty {
                results.append(.warning("KDF Parameters has unexpected additional parameters: \(additional)"))
            }

            if params.salt.count != 32 {
                results.append(.warning("Invalid AES KDF salt length: \(params.salt.count), expected 32 bytes"))
            }

        case let .argon2d(params, additional):
            if !additional.isEmpty {
                results.append(.warning("KDF Parameters has unexpected additional parameters: \(additional)"))
            }

            results += params.validate()

        case let .argon2id(params, additional):
            if !additional.isEmpty {
                results.append(.warning("KDF Parameters has unexpected additional parameters: \(additional)"))
            }

            results += params.validate()

        case let .unknown(uuid):
            results.append(.error("Unsupported KDF UUID: \(uuid)"))
        }

        return results
    }
}

public extension KDFParameters.Argon2 {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        switch version {
        case .v1_0:
            results.append(.warning("Argon2d KDF version 1.0 is not recommended"))
        case .v1_3:
            break
        }

        if salt.count < 8 {
            results.append(.error("Invalid Argon2 KDF salt length: \(salt.count), expected at least 8 bytes. Recommdneded size is 32 bytes"))
        } else if salt.count < 32 {
            results.append(.warning("Argon2 KDF salt length recommended to be 32 bytes, got \(salt.count) bytes"))
        }

        return results
    }
}
