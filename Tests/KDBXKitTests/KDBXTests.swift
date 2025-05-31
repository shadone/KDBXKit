//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct KDBXTests {
    @Test
    func KDBXReaderSimple_Argon2d_AES256() async throws {
        // KDF: argon2d
        // Content encryption: AES256CBC
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-argon2d-aes256", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-argon2d-aes256", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "123"))

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_1)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "57c789c9a7df70a5bb7d10bdae09180a40e35556b8a8064196779219628ddfd4")
        #expect(content.header.encryptionNonce.hexString == "0656009f25f6458a750e210217cd7fc2")

        #expect(content.header.kdfParameters.argon2d != nil)
        #expect(content.header.kdfParameters.argon2d?.params.version == .v1_3)
        #expect(content.header.kdfParameters.argon2d?.params.iterations == 10)
        #expect(content.header.kdfParameters.argon2d?.params.memory == 67_108_864)
        #expect(content.header.kdfParameters.argon2d?.params.parallelism == 12)
        #expect(content.header.kdfParameters.argon2d?.params.salt.hexString == "ddf3bb53e421cf7e2be15ac8556c8228cbb7e0fc60359b61295c6533de645bb7")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.hexString == "89b089183e2dc2c220df1e94feef6d658dacf87dbb4e2a1337e5380f25eed8dc72492e6fb9794329d7fc80b0932ad37a4fca03ae7ea2c17b7e829e5256054496")
        #expect(content.innerHeader.binaryContent.isEmpty == true)

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func KDBXReaderSimple_Argon2id_AES256() async throws {
        // KDF: argon2id
        // Content encryption: AES256CBC
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "123"))

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_0)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "da94766b3643613a3eb6f2a6eab125f2b8f5f4bdcf0dc02bd0e94e9fff8aea38")
        #expect(content.header.encryptionNonce.hexString == "138ccf115923dd1e32d9e70cbc8832b3")

        #expect(content.header.kdfParameters.argon2id != nil)
        #expect(content.header.kdfParameters.argon2id?.params.version == .v1_3)
        #expect(content.header.kdfParameters.argon2id?.params.iterations == 10)
        #expect(content.header.kdfParameters.argon2id?.params.memory == 67_108_864)
        #expect(content.header.kdfParameters.argon2id?.params.parallelism == 12)
        #expect(content.header.kdfParameters.argon2id?.params.salt.hexString == "144c6206ad60ea2bb3fe92522a8553b706e285964440f30b7dbf1d27405c81ef")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.hexString == "f17626dfb97ba00416955501fb794e34f95da47472985d4916accb3e0853c6b6e1c11a42ab6b3265279bd169c16c4a546968deb54760c0a42bc549120f88b55e")
        #expect(content.innerHeader.binaryContent.isEmpty == true)

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func KDBXReaderSimple_AES256_AES256() async throws {
        // KDF: AES256
        // Content encryption: AES256CBC
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "123"))

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_0)
        #expect(content.header.encryptionAlgorithm == .AES256CBC)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "68809cfbd28cb5e5a6292bc47a0f9da676004855179dde445b6f74c4c90e659b")
        #expect(content.header.encryptionNonce.hexString == "371d051e5d4a9acc290498700c6d22a8")

        #expect(content.header.kdfParameters.aes != nil)
        #expect(content.header.kdfParameters.aes?.params.rounds == 1000)
        #expect(content.header.kdfParameters.aes?.params.salt.hexString == "bff164e9044a359f4b473f882d83fe1e85f4e88ac6caf2c28f0c75e24c8e7569")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.hexString == "40b2e668db617d0cd1ed710ec717e4df17ee5f0f3d5abfd06a41b5e8ff4e061308007e8d04a00df48b28184cb141e5564e5b81266a83c4d019cb4a18cfa141d5")
        #expect(content.innerHeader.binaryContent.isEmpty == true)

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func Format400_Argon2d_ChaCha20() async throws {
        // KDF: argon2d
        // Content encryption: ChaCha20
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/Format400", ofType: "kdbx")!
        let xmlFilepath = Bundle.module.path(forResource: "Resources/Format400", ofType: "xml")!
        let data = try Data(contentsOf: URL(filePath: kdbxFilepath))

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: .init(masterPassword: "t"))

        #expect(reader.header != nil)
        #expect(reader.header == content.header)

        #expect(content.header.formatVersion == .v4_0)
        #expect(content.header.encryptionAlgorithm == .ChaCha20)
        #expect(content.header.compressionAlgorithm == .gzip)
        #expect(content.header.masterSalt.hexString == "3bfa79c0795325db317f99f475b559f195d73368da522c12a061a0c2b9efcb13")
        #expect(content.header.encryptionNonce.hexString == "333f87509b6f72908d689430")

        #expect(content.header.kdfParameters.argon2d != nil)
        #expect(content.header.kdfParameters.argon2d?.params.version == .v1_3)
        #expect(content.header.kdfParameters.argon2d?.params.iterations == 2)
        #expect(content.header.kdfParameters.argon2d?.params.memory == 1_048_576)
        #expect(content.header.kdfParameters.argon2d?.params.parallelism == 2)
        #expect(content.header.kdfParameters.argon2d?.params.salt.hexString == "56ac066d2d862ab0c50c00f6143a349df441f2e6910b297da88f50c3c302d9a5")

        #expect(reader.innerHeader != nil)
        #expect(reader.innerHeader == content.innerHeader)

        #expect(content.innerHeader.encryptionAlgorithm == .ChaCha20)
        #expect(content.innerHeader.encryptionKey.hexString == "82e360f53b72fa95c82b32d5129ebe891dd1974f56aeca7221f3ce6ab7b92f4644d0a832501b6eeb05fa2d1bc5a57a532ac3d4954370da171bf558a041ed8c3e")
        #expect(content.innerHeader.binaryContent.isEmpty == false)
        #expect(content.innerHeader.binaryContent[0].shouldBeProtected == false)
        #expect(content.innerHeader.binaryContent[0].data == Data(hexString: "466f726d61743430300a"))

        let xmlDocument = reader.xmlDocument
        #expect(xmlDocument != nil)

        let referenceXmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)
        #expect(xmlDocument == referenceXmlDocument)
    }

    @Test
    func readThenWriteThenReadAgain() async throws {
        let kdbxFilepath = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let referenceKDBXData = try Data(contentsOf: URL(filePath: kdbxFilepath))

        let unlockData = UnlockData(masterPassword: "123")
        var reader = KDBXReader(referenceKDBXData)
        let reference = try reader.parse(unlockData: unlockData)

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try KDBXWriter(to: outputStream).write(reference, unlockData: unlockData)
        let writtenKDBXData = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var reader2 = KDBXReader(writtenKDBXData)
        let readAgain = try reader2.parse(unlockData: unlockData)

        #expect(readAgain == reference)
    }
}
