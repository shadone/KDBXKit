//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

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

        let symKey = SymmetricKey(data: key)
        do {
            let civ = try AES._CBC.IV(ivBytes: iv)
            return try AES._CBC.decrypt(cipherText, using: symKey, iv: civ)
        } catch {
            throw .cryptoFailure(String(describing: error))
        }
    }

    /// AES-256-CBC encrypt with PKCS7 padding.
    static func encrypt(iv: Data, plainText: Data, _ key: Data) throws(Error) -> Data {
        guard iv.count == 16 else { throw .invalidIVSize(iv.count) }
        guard key.count == 32 else { throw .invalidKeySize(key.count) }

        let symKey = SymmetricKey(data: key)
        do {
            let civ = try AES._CBC.IV(ivBytes: iv)
            return try AES._CBC.encrypt(plainText, using: symKey, iv: civ)
        } catch {
            throw .cryptoFailure(String(describing: error))
        }
    }
}
