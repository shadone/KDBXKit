//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import argon2
import Foundation

enum Argon2KDF {
    /// Argon2 failure surface. The vendored P-H-C C library returns a
    /// non-zero error code on bad parameters (memory/iterations/parallelism
    /// out of range, salt too short, etc.). A real vault never trips these
    /// because the header validator rejects out-of-range KDF parameters
    /// upstream — but a crafted file could try, and we don't want to crash
    /// the host process on input. Surface the failure as a typed throw
    /// instead.
    enum Error: Swift.Error, Sendable, Equatable {
        case argonFailure(code: Int32, variant: String)
    }

    /// Argon2id KDF. Returns `SecureBytes` so the derived key is held in
    /// zero-on-deinit storage from the moment it's produced.
    static func argon2id(password: SecureBytes, params: KDFParameters.Argon2) throws(Error) -> SecureBytes {
        try runArgon2(password: password, params: params, variant: "argon2id", hash: argon2id_hash_raw)
    }

    /// Argon2d KDF.
    static func argon2d(password: SecureBytes, params: KDFParameters.Argon2) throws(Error) -> SecureBytes {
        try runArgon2(password: password, params: params, variant: "argon2d", hash: argon2d_hash_raw)
    }

    /// Shared runner — `argon2id_hash_raw` and `argon2d_hash_raw` have
    /// identical signatures and identical error contracts.
    private static func runArgon2(
        password: SecureBytes,
        params: KDFParameters.Argon2,
        variant: String,
        hash: (UInt32, UInt32, UInt32, UnsafeRawPointer?, Int, UnsafeRawPointer?, Int, UnsafeMutableRawPointer?, Int) -> Int32
    ) throws(Error) -> SecureBytes {
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
                hash(
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

        guard Argon2_ErrorCodes(rawValue: result) == ARGON2_OK else {
            throw .argonFailure(code: result, variant: variant)
        }
        return SecureBytes(UnsafeBufferPointer(start: hashPtr, count: hashLength))
    }
}
