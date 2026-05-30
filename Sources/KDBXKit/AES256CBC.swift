//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#endif

enum AES256CBC {
    enum Error: Swift.Error, Sendable, Equatable {
        case invalidIVSize(Int)
        case invalidKeySize(Int)
        case cryptoFailure(String)
    }

    /// AES-256-CBC decrypt with PKCS7 padding.
    static func decrypt(iv: Data, cipherText: Data, _ key: Data) throws(Error) -> Data {
        guard iv.count == 16 else { throw .invalidIVSize(iv.count) }
        guard key.count == 32 else { throw .invalidKeySize(key.count) }
        #if canImport(CommonCrypto)
        // Apple platforms: route through CommonCrypto so AES runs on the
        // CPU's AES instructions (AES-NI / ARMv8 crypto extensions).
        // swift-crypto's `_CryptoExtras.AES._CBC` does NOT engage the
        // hardware path and decrypts at ~33 MB/s vs CommonCrypto's
        // ~6 GB/s — a ~180x difference that dominates vault open time for
        // any file with sizeable attachments.
        return try ccCrypt(operation: CCOperation(kCCDecrypt), iv: iv, input: cipherText, key: key)
        #else
        return try swiftCryptoCrypt(iv: iv, key: key) { symKey, civ in
            try AES._CBC.decrypt(cipherText, using: symKey, iv: civ)
        }
        #endif
    }

    /// AES-256-CBC encrypt with PKCS7 padding.
    static func encrypt(iv: Data, plainText: Data, _ key: Data) throws(Error) -> Data {
        guard iv.count == 16 else { throw .invalidIVSize(iv.count) }
        guard key.count == 32 else { throw .invalidKeySize(key.count) }
        #if canImport(CommonCrypto)
        return try ccCrypt(operation: CCOperation(kCCEncrypt), iv: iv, input: plainText, key: key)
        #else
        return try swiftCryptoCrypt(iv: iv, key: key) { symKey, civ in
            try AES._CBC.encrypt(plainText, using: symKey, iv: civ)
        }
        #endif
    }

    #if canImport(CommonCrypto)
    /// One-shot CommonCrypto AES-256-CBC with PKCS7 padding. `operation`
    /// selects encrypt vs decrypt. Output is sized to `input.count + one
    /// block` (PKCS7 grows by up to a block on encrypt; decrypt only
    /// shrinks) and trimmed to the byte count CommonCrypto actually wrote.
    private static func ccCrypt(operation: CCOperation, iv: Data, input: Data, key: Data) throws(Error) -> Data {
        let outCapacity = input.count + kCCBlockSizeAES128
        var output = Data(count: outCapacity)
        var bytesWritten = 0

        let status = output.withUnsafeMutableBytes { outPtr in
            input.withUnsafeBytes { inPtr in
                iv.withUnsafeBytes { ivPtr in
                    key.withUnsafeBytes { keyPtr in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            inPtr.baseAddress, input.count,
                            outPtr.baseAddress, outCapacity,
                            &bytesWritten
                        )
                    }
                }
            }
        }

        guard status == CCCryptorStatus(kCCSuccess) else {
            throw .cryptoFailure("CCCrypt failed with status \(status)")
        }
        output.removeSubrange(bytesWritten..<output.count)
        return output
    }
    #else
    /// swift-crypto fallback (non-Apple, e.g. Linux). Correct but does not
    /// engage hardware AES; acceptable on the CLI/CI lane where Apple's
    /// CommonCrypto is unavailable.
    private static func swiftCryptoCrypt(
        iv: Data,
        key: Data,
        _ body: (SymmetricKey, AES._CBC.IV) throws -> Data
    ) throws(Error) -> Data {
        let symKey = SymmetricKey(data: key)
        do {
            let civ = try AES._CBC.IV(ivBytes: iv)
            return try body(symKey, civ)
        } catch {
            throw .cryptoFailure(String(describing: error))
        }
    }
    #endif
}
