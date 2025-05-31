//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct Salsa20SmallTests {
    let encryptedStream = [
        "oIY/Sf4NEFo2",
        "QF5G0y5tySZczA==",
        "QgQ6JeN3wIyV",
        "LM34s0JbWtygoQ==",
        "94nu5uWkp4/oHg==",
    ]
    let plaintextStream = [
        "firstpass",
        "secondpass",
        "thirdpass",
        "fourthpass",
        "fifrthpass",
    ]
    let key = Data(hexString: "fd37703ae81a2ef03fb8f666b400fa76aebb0d9ae16cc10dd946fe48170f507f")!
    let nonce = Data(hexString: "9c6f4801e7bb631e")!

    @Test
    func decrypt() throws {
        let salsa20 = try Salsa20(key: Array(key), iv: Array(nonce))

        let decryptedStream = encryptedStream.map { ciphertext in
            let data = Data(base64Encoded: ciphertext)!
            let decrypted = salsa20.decrypt(Array(data))
            let decryptedString = String(validating: Data(decrypted), as: UTF8.self)!
            return decryptedString
        }

        #expect(decryptedStream == plaintextStream)
    }

    @Test
    func encrypt() throws {
        let salsa20 = try Salsa20(key: Array(key), iv: Array(nonce))

        let encrypted = plaintextStream.map { plaintext in
            let encrypted = salsa20.encrypt(Array(plaintext.data(using: .utf8)!))
            return Data(encrypted).base64EncodedString()
        }

        #expect(encrypted == encryptedStream)
    }
}

struct Salsa20LargerTests {
    let encryptedStream = [
        "Ob755R+tufKWSw==",
        "lt2+oYvOyWOG/g==",
        "8SlMakhy+QY7Ww==",
        "ZddwQak1DSP7Tw==",
        "nCW4H1JEj2STXbJmTvdkLZBoySDP30DmSKWYoyJSivnoMxCo4wqDKmXq0lnIwLmPTntYXynuNt6RFk3i6u5w7bZ3+akKRjwfot+Kq2crBdd369+F6yhMHQ==",
        "vcsDjISSwUEtYyQ=",
        "SOPs",
        "ZMMyVCyNxOxkJeM=",
        "DkYGtFVNZWRTZlQ=",
        "b0Tq",
    ]
    let plaintextStream = [
        "mypassword",
        "mypassword",
        "mypassword",
        "mypassword",
        "mypasswordsfsffwerwerwrwerwrwerwrwrlkjfghadkjhgksdjhgdksjhgdkjhgdskjhgdskjhgksdjhgdskjhg",
        "gitblahpass",
        "baz",
        "gitblahpass",
        "gitblahpass",
        "baz",
    ]
    let key = Data(hexString: "d9802f14c6fc7960c082378df1ef1a6cb5cc3bc9158d530e7f27545bc5681d39")!
    let nonce = Data(hexString: "546a328650b81304")!

    @Test
    func decrypt() throws {
        let salsa20 = try Salsa20(key: Array(key), iv: Array(nonce))

        let decryptedStream = encryptedStream.map { ciphertext in
            let data = Data(base64Encoded: ciphertext)!
            let decrypted = salsa20.decrypt(Array(data))
            let decryptedString = String(validating: Data(decrypted), as: UTF8.self)!
            return decryptedString
        }

        #expect(decryptedStream == plaintextStream)
    }

    @Test
    func encrypt() throws {
        let salsa20 = try Salsa20(key: Array(key), iv: Array(nonce))

        let encrypted = plaintextStream.map { plaintext in
            let encrypted = salsa20.encrypt(Array(plaintext.data(using: .utf8)!))
            return Data(encrypted).base64EncodedString()
        }

        #expect(encrypted == encryptedStream)
    }
}
