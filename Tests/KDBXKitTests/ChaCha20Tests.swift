//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct ChaCha20Tests {
    let encryptedStream = [
        "9BhckZHucS1h",
        "zYDsn0pD+YVmDA==",
        "Cmg8MVd3IByp",
        "YXxSvAfX/e4FBw==",
        "DsJkk8yY2Bm+/g==",
    ]
    let plaintextStream = [
        "firstpass",
        "secondpass",
        "thirdpass",
        "fourthpass",
        "fifrthpass",
    ]
    let key = Data(hexString: "fd37703ae81a2ef03fb8f666b400fa76aebb0d9ae16cc10dd946fe48170f507f")!
    let nonce = Data(hexString: "9c6f4801e7bb631e9e8ec4a3")!

    @Test
    func decrypt() throws {
        let chaCha20 = try ChaCha20(key: Array(key), iv: Array(nonce))

        let decryptedStream = encryptedStream.map { ciphertext in
            let data = Data(base64Encoded: ciphertext)!
            let decrypted = chaCha20.decrypt(Array(data))
            let decryptedString = String(validating: Data(decrypted), as: UTF8.self)!
            return decryptedString
        }

        #expect(decryptedStream == plaintextStream)
    }

    @Test
    func encrypt() throws {
        let chaCha20 = try ChaCha20(key: Array(key), iv: Array(nonce))

        let encrypted = plaintextStream.map { plaintext in
            let encrypted = chaCha20.encrypt(Array(plaintext.data(using: .utf8)!))
            return Data(encrypted).base64EncodedString()
        }

        print(encrypted)
        #expect(encrypted == encryptedStream)
    }
}
