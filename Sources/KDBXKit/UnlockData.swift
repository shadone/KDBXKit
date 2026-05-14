//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoKit
import Foundation

/// Errors raised while turning a user-provided key into a vault unlock key.
public enum UnlockDataError: Error, Sendable {
    /// The KDF identified by this UUID isn't implemented by KDBXKit. The
    /// reader records the UUID from the file's KDF parameters so the caller
    /// can describe what the file used.
    case unsupportedKDF(UUID)
}

/// Container for the key data needed to unlock a `.kdbx` file.
///
/// KDBX derives the unlock key in two passes:
///
/// 1. **Pre-hash.** `R = SHA-256(SHA-256(password.utf8) || keyFile)`.
///    Components are optional: at least one of password or key file must be
///    provided. (Key-provider plugins and Windows DPAPI keys from the spec
///    aren't currently supported.)
/// 2. **KDF.** `T = KDF(R)` where the KDF and its parameters are stored in
///    the file header. Supported: AES-KDF, Argon2d, Argon2id.
///
/// `UnlockData` performs step 1 at init and **discards the cleartext
/// password buffer immediately**. Swift `String` can't be securely zeroed,
/// so keeping the password around longer than necessary is a real concern
/// for a password manager — by storing only the 32-byte pre-hash internally
/// we shorten the cleartext lifetime to the init call frame.
///
/// `UnlockData` is `Sendable`, so it can be passed across actor boundaries
/// (e.g. from the UI thread to a detached writer task).
///
/// https://keepass.info/help/kb/kdbx.html#keys
public struct UnlockData: Sendable {
    /// The 32-byte pre-hash R, held in zero-on-deinit storage. Combined with
    /// the file's KDF salt + parameters to produce the unlock key. Stored as
    /// `SecureBytes` rather than `Data` so the buffer is `mlock`'d and the
    /// bytes are zeroed when the last reference releases.
    let keyData: SecureBytes

    /// Build an unlock from a master password and an optional key file.
    public init(masterPassword: String, keyFile: Data? = nil) {
        keyData = Self.makeKeyData(password: masterPassword, keyFile: keyFile)
    }

    /// Build an unlock from a key file alone (no password).
    public init(keyFile: Data) {
        keyData = Self.makeKeyData(password: nil, keyFile: keyFile)
    }

    /// Build an unlock from already-derived key data — used by tests and
    /// integrations that have the SHA-256 pre-hash in hand. Internal because
    /// public callers should go through the password / key-file initializers.
    init(rawKeyData: Data) {
        precondition(rawKeyData.count == 32, "Raw key data must be SHA-256-sized (32 bytes)")
        keyData = SecureBytes(rawKeyData)
    }

    /// Run the KDF identified by `kdfParameters` against this unlock's key
    /// data, producing the 32-byte transformed key `T` from the KDBX spec.
    /// Throws `UnlockDataError.unsupportedKDF` when the KDF UUID in the file
    /// isn't one of AES-KDF / Argon2d / Argon2id.
    func computeUnlockKey(kdfParameters: KDFParameters) throws(UnlockDataError) -> SecureBytes {
        switch kdfParameters {
        case let .aes(params, _):
            return AESKDF.derive(salt: params.salt, rounds: params.rounds, keyData)

        case let .argon2d(params, _):
            return Argon2KDF.argon2d(password: keyData, params: params)

        case let .argon2id(params, _):
            return Argon2KDF.argon2id(password: keyData, params: params)

        case let .unknown(uuid):
            throw .unsupportedKDF(uuid)
        }
    }

    private static func makeKeyData(password: String?, keyFile: Data?) -> SecureBytes {
        // R = SHA-256( SHA-256(password.utf8) || keyFile )
        var hasher = SHA256()
        if let password {
            // String → UTF-8 cannot fail.
            let utf8 = password.data(using: .utf8)!
            hasher.update(data: utf8.sha256())
        }
        if let keyFile {
            hasher.update(data: keyFile)
        }
        return SecureBytes(Data(hasher.finalize()))
    }
}
