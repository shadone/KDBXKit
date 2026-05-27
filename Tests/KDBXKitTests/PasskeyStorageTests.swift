//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite struct PasskeyStorageTests {
    private func loadFixturePasskeys() throws -> [KDBX.Entry] {
        let path = Bundle.module.path(forResource: "Resources/kpxc-passkey", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: UnlockData(masterPassword: "123"))
        var found: [KDBX.Entry] = []
        content.database.visitEntries(in: content.database.root.group) { entry in
            if entry.isPasskey { found.append(entry) }
        }
        return found
    }

    @Test func readsPasskeysFromKeePassXCFixture() throws {
        let passkeys = try loadFixturePasskeys()
        #expect(passkeys.count == 6)
        let ctap = try #require(passkeys.first { $0.passkeyRelyingParty == "ctap.dev" })
        #expect(ctap.passkeyUsername?.isEmpty == false)
        #expect(ctap.passkeyCredentialID != nil)
        #expect(ctap.passkeyUserHandle != nil)
        let pem = try #require(ctap.passkeyPrivateKeyPEM)
        pem.withRevealedString { #expect($0.contains("PRIVATE KEY")) }
    }
}
