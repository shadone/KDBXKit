//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBXReader static API")
struct StaticReaderAPITests {

    @Test("parse(data, unlockData:) returns content in one call")
    func staticParse() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        #expect(content.header.formatVersion == .v4_0)
        #expect(content.database.meta.databaseName != nil)
    }

    @Test("parseHeader(data) inspects without credentials")
    func staticParseHeader() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        let header = try KDBXReader.parseHeader(data)
        #expect(header.formatVersion == .v4_0)
        #expect(header.encryptionAlgorithm == .AES256CBC)
        #expect(header.compressionAlgorithm == .gzip)
        // Public custom data should be empty for these fixtures.
        #expect(header.publicCustomData.isEmpty)
    }

    @Test("parse with wrong password throws .wrongCredentials")
    func wrongPasswordSurfacesStructuredError() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(data, unlockData: .init(masterPassword: "wrong"))
        }
    }

    @Test("parseHeader on a non-KDBX file throws .invalidFileSignature")
    func invalidSignatureSurfacesStructuredError() throws {
        let bogus = Data("not a kdbx file at all".utf8) + Data(repeating: 0, count: 200)

        #expect(throws: KDBXReader.Error.invalidFileSignature) {
            _ = try KDBXReader.parseHeader(bogus)
        }
    }
}
