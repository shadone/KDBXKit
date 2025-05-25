//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Test
func KDBXReaderSimple() async throws {
    let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-argon2d-aes256", ofType: "kdbx")!
    let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-argon2d-aes256", ofType: "xml")!
    let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

    var reader = KDBXReader(data)
    let xmlDocument = try reader.parse(unlockData: .init(masterPassword: "123"))

    #expect(reader.header != nil)

    #expect(reader.header?.formatVersion == .v4_0)
    #expect(reader.header?.encryptionAlgorithm == .AES256CBC)
    #expect(reader.header?.compressionAlgorithm == .gzip)
    #expect(reader.header?.masterSalt.hexString == "57c789c9a7df70a5bb7d10bdae09180a40e35556b8a8064196779219628ddfd4")
    #expect(reader.header?.encryptionNonce.hexString == "0656009f25f6458a750e210217cd7fc2")

    #expect(reader.header?.kdfParameters.argon2d != nil)
    #expect(reader.header?.kdfParameters.argon2d?.params.version == .v1_3)
    #expect(reader.header?.kdfParameters.argon2d?.params.iterations == 10)
    #expect(reader.header?.kdfParameters.argon2d?.params.memory == 67108864)
    #expect(reader.header?.kdfParameters.argon2d?.params.parallelism == 12)
    #expect(reader.header?.kdfParameters.argon2d?.params.salt.hexString == "ddf3bb53e421cf7e2be15ac8556c8228cbb7e0fc60359b61295c6533de645bb7")

    #expect(reader.innerHeader != nil)
    #expect(reader.innerHeader?.encryptionAlgorithm == .ChaCha20)
    #expect(reader.innerHeader?.encryptionKey.hexString == "89b089183e2dc2c220df1e94feef6d658dacf87dbb4e2a1337e5380f25eed8dc72492e6fb9794329d7fc80b0932ad37a4fca03ae7ea2c17b7e829e5256054496")
    #expect(reader.innerHeader?.binaryContent.count == 0)

    let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
    #expect(xmlDocument == referenceXmlDocument)
}
