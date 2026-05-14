//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CommonCrypto
import Foundation

enum AESKDF {
    /// Returns `SecureBytes` so the derived key is held in zero-on-deinit
    /// storage from the moment it's produced.
    static func derive(salt: Data, rounds: UInt64, _ password: SecureBytes) -> SecureBytes {
        precondition(salt.count == 32, "AESKDF: Invalid salt size")
        precondition(password.count == kCCKeySizeAES256, "AESKDF: Invalid key size \(password.count) != \(kCCKeySizeAES256)")

        // `buffer` is the running AES-encrypted state. It holds key material;
        // we use a Data here for the in-loop arithmetic (slicing + concat) but
        // wrap the final result in SecureBytes. The transient Data is zeroed
        // before this function returns.
        var buffer = password.toData()
        defer {
            buffer.withUnsafeMutableBytes { ptr in
                ptr.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        // Is this correct? Couldn't find much documentation about Keepass AES KDF implementation.
        // There are some bits and pieces on the internet, including in The Wayback Machine, but
        // not clear algorithm described.
        // https://keepass.info/help/base/security.html
        // https://keepass.info/help/kb/kdbx.html
        // https://keepass.info/help/kb/kdbx_4.html
        //
        // The following implementation was suggested by ChatGPT and seems to work on my small
        // test kdbx database.
        //
        // ¯\_(ツ)_/¯

        for _ in 0..<rounds {
            let left = buffer.prefix(16)
            let right = buffer.suffix(16)

            let encryptedLeft = aes256EncryptBlockECB(input: left, key: salt)
            let encryptedRight = aes256EncryptBlockECB(input: right, key: salt)

            buffer = encryptedLeft + encryptedRight
        }

        return SecureBytes(buffer.sha256())
    }

    private static func aes256EncryptBlockECB(input: Data, key: Data) -> Data {
        precondition(input.count == kCCBlockSizeAES128, "AESKDF: Invalid input size \(input.count) != \(kCCBlockSizeAES128)")
        precondition(key.count == kCCKeySizeAES256, "AESKDF: Invalid key size \(key.count) != \(kCCKeySizeAES256)")

        // TODO: This function is very slow, the implemtation is naive

        let cipherTextSize = kCCBlockSizeAES128
        let cipherTextPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: cipherTextSize)

        defer { cipherTextPtr.deallocate() }
        var actualCipherTextSize = 0

        let status = input.withUnsafeBytes { inputPtr in
            key.withUnsafeBytes { keyPtr in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyPtr.baseAddress,
                    key.count,
                    nil,
                    inputPtr.baseAddress,
                    input.count,
                    cipherTextPtr,
                    cipherTextSize,
                    &actualCipherTextSize
                )
            }
        }

        switch Int(status) {
        case kCCSuccess:
            return Data(bytes: cipherTextPtr, count: actualCipherTextSize)

        case kCCBufferTooSmall:
            fatalError("AESKDF: Buffer too small \(cipherTextSize)")

        default:
            fatalError("AESKDF: error \(status)")
        }
    }
}
