//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import argon2
import Foundation

enum Argon2KDF {
    /// Argon2id KDF. Returns `SecureBytes` so the derived key is held in
    /// zero-on-deinit storage from the moment it's produced.
    static func argon2id(password: SecureBytes, params: KDFParameters.Argon2) -> SecureBytes {
        let hashLength = 32
        let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: hashLength)
        defer {
            // Best-effort zero before deallocate so the allocator doesn't
            // hand the buffer (with key bytes still in it) to another caller.
            hashPtr.update(repeating: 0, count: hashLength)
            hashPtr.deallocate()
        }

        let result = password.withUnsafeBytes { passwordPtr in
            params.salt.withUnsafeBytes { saltPtr in
                argon2id_hash_raw(
                    UInt32(params.iterations),
                    UInt32(params.memory / 1024), // argon2 expects memory cost in kibibytes
                    params.parallelism,
                    passwordPtr.baseAddress,
                    password.count,
                    saltPtr.baseAddress,
                    params.salt.count,
                    hashPtr,
                    hashLength
                )
            }
        }

        let code = Argon2_ErrorCodes(rawValue: result)
        switch code {
        case ARGON2_OK:
            return SecureBytes(UnsafeBufferPointer(start: hashPtr, count: hashLength))
        default:
            fatalError("Argon2id: error\(code)")
        }
    }

    /// Argon2d KDF.
    static func argon2d(password: SecureBytes, params: KDFParameters.Argon2) -> SecureBytes {
        let hashLength = 32
        let hash = UnsafeMutablePointer<UInt8>.allocate(capacity: hashLength)
        defer {
            hash.update(repeating: 0, count: hashLength)
            hash.deallocate()
        }

        let result = password.withUnsafeBytes { passwordPtr in
            params.salt.withUnsafeBytes { saltPtr in
                argon2d_hash_raw(
                    UInt32(params.iterations),
                    UInt32(params.memory / 1024), // argon2 expects memory cost in kibibytes
                    params.parallelism,
                    passwordPtr.baseAddress,
                    password.count,
                    saltPtr.baseAddress,
                    params.salt.count,
                    hash,
                    hashLength
                )
            }
        }

        let code = Argon2_ErrorCodes(rawValue: result)
        switch code {
        case ARGON2_OK:
            return SecureBytes(UnsafeBufferPointer(start: hash, count: hashLength))
        default:
            fatalError("Argon2id error: \(code)")
        }
    }
}
