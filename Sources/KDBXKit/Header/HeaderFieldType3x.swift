//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Header fields used by the KDBX 3.x file format.
///
/// The 3.x header is similar in spirit to 4.x (TLV stream terminated by an
/// `endOfHeader` marker) but field lengths are `UInt16`, KDF parameters live
/// in dedicated fields rather than a `VariantDictionary`, and the inner
/// stream cipher (used to protect XML password fields) is configured here
/// rather than in a separate inner header.
///
/// 3.x reserves a few legacy IDs that 4.x reuses with new semantics
/// (notably `kdfParameters = 11`), so a separate enum keeps the two
/// dialects from accidentally aliasing.
enum HeaderFieldType3x: UInt8 {
    /// Indicates the end of the header. Must be present exactly once, as the
    /// last header field. Value is the byte array `0x0D, 0x0A, 0x0D, 0x0A`.
    case endOfHeader = 0

    /// The value of the TLV field for `endOfHeader`.
    static let endOfHeaderValue = Data([0x0D, 0x0A, 0x0D, 0x0A])

    /// Optional comment. Not normally produced by mainstream writers; if
    /// present it is ignored.
    case comment = 1

    /// Outer encryption algorithm UUID. KDBX 3.x supports AES-256-CBC only.
    ///
    /// Value type: `UUID` (`Byte[16]`).
    case cipherID = 2

    /// Outer compression flag. `0` = none, `1` = gzip.
    ///
    /// Value type: `UInt32`.
    case compressionFlags = 3

    /// Master seed (32 bytes). Mixed with the transformed composite key to
    /// derive both the AES-CBC content key and the HMAC keys (4.x naming:
    /// "masterSalt"). Regenerated on every save.
    case masterSeed = 4

    /// AES-KDF transform seed (32 bytes). The "salt" parameter for AES-KDF.
    /// Regenerated on every save.
    case transformSeed = 5

    /// AES-KDF transform rounds (`UInt64`). Number of AES-ECB iterations
    /// applied to the composite key.
    case transformRounds = 6

    /// AES-CBC initialization vector (16 bytes).
    case encryptionIV = 7

    /// Inner-stream-cipher key (32 bytes). Keys the Salsa20 (or in 3.0
    /// optionally ArcFour-variant) keystream used to XOR-protect the
    /// `<Value Protected="True">` strings in the XML body.
    case protectedStreamKey = 8

    /// Stream-start bytes (32 bytes). After AES-CBC decrypting the body,
    /// the first 32 plaintext bytes must equal this value — a structural
    /// integrity check that pre-dates the 4.x HMAC scheme.
    case streamStartBytes = 9

    /// Inner random stream cipher ID (`UInt32`). The cipher used to derive
    /// the keystream for protected XML strings. `2` = Salsa20 (3.1
    /// default), `1` = ArcFour-variant (3.0 legacy, not supported), `3` =
    /// ChaCha20 (4.x).
    case innerRandomStreamID = 10
}
