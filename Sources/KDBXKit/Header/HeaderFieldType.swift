//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Header fields supported by KDBX4 file format.
///
/// The raw value is the `ID t (byte)`.
///
/// The IDs 1, 5, 6, 8, 9 and 10 were used in previous versions of the KDBX file format.
enum HeaderFieldType: UInt8 {
    /// Indicates the end of the header. Must be present exactly once, as the last header field.
    ///
    /// Value type: `Byte[4]`
    ///
    /// The value should be the byte array `0x0D, 0x0A, 0x0D, 0x0A`.
    case endOfHeader = 0

    /// The value of the TLV field for `endOfHeader` field.
    static let endOfHeaderValue = Data([0x0D, 0x0A, 0x0D, 0x0A])

    /// The encryption algorithm for the inner content (inner header and the XML document).
    ///
    /// The following encryption algorithms are supported by KeePass (built-in, without a plugin):
    ///
    /// - `31C1F2E6BF714350BE5805216AFC5AFF`: AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding).
    /// - `D6038A2B8B6F4CB5A524339A31DBB59A`: ChaCha20 (RFC 8439).
    ///
    /// Plugins can provide more encryption algorithms.
    ///
    /// Value type: `UUID`
    case encryptionAlgorithm = 2

    /// Specifies whether the inner content (inner header and the XML document) is compressed.
    ///
    /// 0 = no compression, 1 = GZip.
    ///
    /// Value type: `UInt32`
    case compressionAlgorithm = 3

    /// Master salt/seed (⟳)
    ///
    /// Salt/seed for [computing the keys](https://keepass.info/help/kb/kdbx.html#keys).
    ///
    /// - note: Must be regenerated each time KDBX file is saved!
    ///
    /// Value type: `Byte[32]`
    case masterSalt = 4

    /// Encryption IV/nonce (⟳)
    ///
    /// Initialization vector or nonce for the encryption algorithm. 16 bytes for AES-256, 12 bytes for ChaCha20.
    ///
    /// - note: Must be regenerated each time KDBX file is saved!
    ///
    /// Value type: `Byte[]`
    case encryptionNonce = 7

    /// KDF parameters
    ///
    /// Parameters for the key derivation function (KDF). See below
    ///
    /// Value type: [`Variant dictionary`](https://keepass.info/help/kb/kdbx.html#vardict).
    case kdfParameters = 11

    /// Custom data of plugins/ports.
    ///
    /// The name of an item should be unique, e.g. `"PluginName_ItemName"`.
    ///
    /// In this header field, only data that must be readable without decryption should be stored (e.g. data by a key provider plugin
    /// required for decryption). All other custom data should be stored in the encrypted XML document
    /// (elements `//Meta/CustomData`, `//Group/CustomData` and `//Entry/CustomData`).
    ///
    /// Value type: [`Variant dictionary`](https://keepass.info/help/kb/kdbx.html#vardict).
    case publicCustomData = 12
}
