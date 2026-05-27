//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite struct PasskeyStorageTests {
    private func loadFixture() throws -> KDBXContent {
        let path = Bundle.module.path(forResource: "Resources/kpxc-passkey", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        var reader = KDBXReader(data)
        return try reader.parse(unlockData: UnlockData(masterPassword: "123"))
    }

    private func loadFixturePasskeys() throws -> [KDBX.Entry] {
        let content = try loadFixture()
        var found: [KDBX.Entry] = []
        content.database.visitEntries(in: content.database.root.group) { entry in
            if entry.isPasskey { found.append(entry) }
        }
        return found
    }

    @Test func noParserWarningsOnKeePassXCFixture() throws {
        let content = try loadFixture()
        #expect(content.parserWarnings.isEmpty)
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

    @Test func allPasskeysHaveDecodableCredentialIDAndUserHandle() throws {
        let passkeys = try loadFixturePasskeys()
        #expect(passkeys.count == 6)
        for passkey in passkeys {
            let rp = passkey.passkeyRelyingParty ?? "<nil>"
            let credID = passkey.passkeyCredentialID
            #expect(credID != nil, "expected non-nil credentialID for relying party \(rp)")
            #expect((credID?.isEmpty == false) == true,
                    "expected non-empty credentialID for relying party \(rp)")
            let userHandle = passkey.passkeyUserHandle
            #expect(userHandle != nil, "expected non-nil userHandle for relying party \(rp)")
            #expect((userHandle?.isEmpty == false) == true,
                    "expected non-empty userHandle for relying party \(rp)")
        }
    }

    /// Verifies that `fromPasskeyBase64URL` correctly substitutes `-` -> `+`
    /// and `_` -> `/` when decoding. The raw bytes `[0xFB, 0xFF, 0xBF]`
    /// encode to `+/+/` in standard base64 (no padding needed for 3 bytes),
    /// which becomes `-_-_` in base64url. Confirming the round-trip proves
    /// the substitution is wired in both directions.
    ///
    /// Choice: keep `fromPasskeyBase64URL` `internal` (not `private`) so this
    /// test can call it directly and assert the substitution behaviour at the
    /// unit level, rather than relying solely on indirect evidence through a
    /// full vault parse.
    @Test func base64urlDecodeSubstitution() {
        let raw = Data([0xFB, 0xFF, 0xBF])
        // Standard base64 of these bytes is "+/+/" (3 bytes = 4 base64 chars, no padding).
        // base64url form replaces + with - and / with _: "-_-_"
        let base64url = "-_-_"
        let decoded = Data.fromPasskeyBase64URL(base64url)
        #expect(decoded == raw)
    }
}
