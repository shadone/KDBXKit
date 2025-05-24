//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import argon2
import Foundation

func argon2id(password: Data, params: KDFParameters.Argon2) -> Data {
    let hashLength = 32
    let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: hashLength)
    defer { hashPtr.deallocate() }

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
        return Data(bytes: hashPtr, count: hashLength)
    default:
        fatalError("Argon2id: error\(code)")
    }
}

func argon2d(password: Data, params: KDFParameters.Argon2) -> Data {
    let hashLength = 32
    let hash = UnsafeMutablePointer<UInt8>.allocate(capacity: hashLength)
    defer { hash.deallocate() }

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
        return Data(bytes: hash, count: hashLength)
    default:
        fatalError("Argon2id error: \(code)")
    }
}
