//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CommonCrypto
import Foundation

enum AES256CBC {
    static func decrypt(iv: Data, cipherText: Data, _ key: Data) -> Data {
        precondition(iv.count == kCCBlockSizeAES128, "AES256CBC: Invalid IV size \(iv.count)")
        precondition(key.count == kCCKeySizeAES256, "AES256CBC: Invalid key size \(key.count)")

        // Lets assume the decrypted payload will not be larger than its encrypted form
        let bufferSize = cipherText.count
        let payloadPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { payloadPtr.deallocate() }
        var actualPayloadSize = 0

        let status = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                cipherText.withUnsafeBytes { cipherTextPtr in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyPtr.baseAddress,
                        kCCKeySizeAES256,
                        ivPtr.baseAddress,
                        cipherTextPtr.baseAddress,
                        cipherText.count,
                        payloadPtr,
                        bufferSize,
                        &actualPayloadSize
                    )
                }
            }
        }

        switch Int(status) {
        case kCCSuccess:
            return Data(bytes: payloadPtr, count: actualPayloadSize)

        case kCCBufferTooSmall:
            fatalError("AES256CBC: Buffer too small \(bufferSize)")

        default:
            fatalError("AES256CBC: error \(status)")
        }
    }
}
