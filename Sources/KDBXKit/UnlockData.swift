//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import CryptoKit

/// Container for the key data needed for unlocking the `.kdbx` content.
///
/// For some of the cryptographic primitives used in the KDBX file format, a key is required. The keys are computed as follows:
///
/// ```
/// 1. Let R be the SHA-256 hash of the concatenation of the components of the master key that the user has provided (each optional, in the following order):
///    a. SHA-256 hash of the master password (encoded using UTF-8).
///    b. Key stored in a key file.
///    c. Key provided by a key provider plugin.
///    d. Key protected using the Windows user account (DPAPI).
/// 2. Let T be the result of transforming R using a key derivation function. The function and parameters for it are stored in the header.
/// ```
///
/// https://keepass.info/help/kb/kdbx.html#keys
public struct UnlockData {
    let masterPassword: String?
    let keyFile: Data?

    public init(masterPassword: String, keyFile: Data? = nil) {
        self.masterPassword = masterPassword
        self.keyFile = keyFile
    }

    public init(keyFile: Data) {
        masterPassword = nil
        self.keyFile = keyFile
    }

    func makeKeyData() -> Data {
        // Let R be the SHA-256 hash of the concatenation of the components of the master key
        // that the user has provided (each optional, in the following order):
        var r = SHA256()

        // 1. SHA-256 hash of the master password (encoded using UTF-8).
        if let masterPassword {
            let utf8 = masterPassword.data(using: .utf8)! // Swift.String -> utf8 cannot fail
            r.update(data: utf8.sha256())
        }

        // 2. Key stored in a key file.
        if let keyFile {
            r.update(data: keyFile)
        }

        // 3. Key provided by a key provider plugin.
        // 4. Key protected using the Windows user account (DPAPI).

        return Data(r.finalize())
    }

    func computeUnlockKey(
        salt _: Data,
        kdfParameters: KDFParameters
    ) -> Data {
        let keydata = makeKeyData()

        // Let T be the result of transforming R using a key derivation function. The function and
        // parameters for it are stored in the header.
        switch kdfParameters {
        case .aes(let params, additional: _):
            return AESKDF.derive(salt: params.salt, rounds: params.rounds, keydata)

        case .argon2d(let params, additional: _):
            return Argon2KDF.argon2d(password: keydata, params: params)

        case .argon2id(let params, additional: _):
            return Argon2KDF.argon2id(password: keydata, params: params)

        case .unknown:
            fatalError("Internal error: unknown KDF")
        }
    }
}
