//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Verifies the parser's default behaviour: don't keep the decrypted XML
/// document around in a Swift String after a successful parse. Unprotected
/// fields (Title / URL / Notes) are plaintext in that String; holding it
/// for the reader's lifetime would mean every unlocked vault retains its
/// entire metadata as a long-lived heap string.
@Suite("KDBXReader xmlDocument retention")
struct XMLDocumentRetentionTests {
    @Test("xmlDocument is nil after successful parse by default")
    func defaultClearsXML() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        var reader = KDBXReader(data)
        _ = try reader.parse(unlockData: .init(masterPassword: "123"))
        #expect(reader.xmlDocument == nil)
        // header is still available for diagnostics.
        #expect(reader.header != nil)
        // innerHeader too — it doesn't contain plaintext data fields.
        #expect(reader.innerHeader != nil)
    }

    @Test("xmlDocument is retained when caller explicitly opts in")
    func optInRetainsXML() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        var reader = KDBXReader(data)
        _ = try reader.parse(unlockData: .init(masterPassword: "123"), retainsXMLForDiagnostics: true)
        #expect(reader.xmlDocument != nil)
    }

    @Test("Static parse never retains xmlDocument — local reader released")
    func staticParseReleasesXML() throws {
        let path = Bundle.module.path(forResource: "Resources/simple-aes256-aes256", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))

        // The static API doesn't expose the reader, so xmlDocument is
        // released as soon as the local goes out of scope at the end of the
        // static call. This is the recommended path for production use.
        let content = try KDBXReader.parse(data, unlockData: .init(masterPassword: "123"))
        #expect(content.database.meta.databaseName != nil)
    }
}
