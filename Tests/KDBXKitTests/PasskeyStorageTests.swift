//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite
struct PasskeyStorageTests {
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

    @Test
    func noParserWarningsOnKeePassXCFixture() throws {
        let content = try loadFixture()
        #expect(content.parserWarnings.isEmpty)
    }

    @Test
    func readsPasskeysFromKeePassXCFixture() throws {
        let passkeys = try loadFixturePasskeys()
        #expect(passkeys.count == 6)
        let ctap = try #require(passkeys.first { $0.passkeyRelyingParty == "ctap.dev" })
        #expect(ctap.passkeyUsername?.isEmpty == false)
        #expect(ctap.passkeyCredentialID != nil)
        #expect(ctap.passkeyUserHandle != nil)
        let pem = try #require(ctap.passkeyPrivateKeyPEM)
        pem.withRevealedString { #expect($0.contains("PRIVATE KEY")) }
    }

    @Test
    func allPasskeysHaveDecodableCredentialIDAndUserHandle() throws {
        let passkeys = try loadFixturePasskeys()
        #expect(passkeys.count == 6)
        for passkey in passkeys {
            let rp = passkey.passkeyRelyingParty ?? "<nil>"
            let credID = passkey.passkeyCredentialID
            #expect(credID != nil, "expected non-nil credentialID for relying party \(rp)")
            #expect(
                (credID?.isEmpty == false) == true,
                "expected non-empty credentialID for relying party \(rp)"
            )
            let userHandle = passkey.passkeyUserHandle
            #expect(userHandle != nil, "expected non-nil userHandle for relying party \(rp)")
            #expect(
                (userHandle?.isEmpty == false) == true,
                "expected non-empty userHandle for relying party \(rp)"
            )
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
    @Test
    func base64urlDecodeSubstitution() {
        let raw = Data([0xFB, 0xFF, 0xBF])
        // Standard base64 of these bytes is "+/+/" (3 bytes = 4 base64 chars, no padding).
        // base64url form replaces + with - and / with _: "-_-_"
        let base64url = "-_-_"
        let decoded = Data.fromPasskeyBase64URL(base64url)
        #expect(decoded == raw)
    }

    // MARK: - Setter tests

    @Test
    func writesAndReadsBackPasskeyFields() throws {
        var entry = KDBX.Entry(uuid: UUID())
        entry.setPasskeyRelyingParty("example.com")
        entry.setPasskeyUsername("alice")
        entry.setPasskeyCredentialID(Data([0x01, 0x02, 0x03, 0x04]))
        entry.setPasskeyUserHandle(Data([0xAA, 0xBB]))
        entry.setPasskeyPrivateKeyPEM("-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----")

        #expect(entry.isPasskey)
        #expect(entry.passkeyRelyingParty == "example.com")
        #expect(entry.passkeyUsername == "alice")
        #expect(entry.passkeyCredentialID == Data([0x01, 0x02, 0x03, 0x04]))
        #expect(entry.passkeyUserHandle == Data([0xAA, 0xBB]))

        // Protection markers must match KeePassXC.
        func proto(_ key: String) -> KDBX.ProtectedString.Value? {
            entry.strings.first { $0.key == key }?.value
        }
        if case .regular = proto(KDBX.Entry.PasskeyField.relyingParty) {} else {
            Issue.record("RP must be .regular")
        }
        if case .regular = proto(KDBX.Entry.PasskeyField.username) {} else {
            Issue.record("username must be .regular")
        }
        if case .unprotected = proto(KDBX.Entry.PasskeyField.credentialID) {} else {
            Issue.record("credID must be .unprotected")
        }
        if case .unprotected = proto(KDBX.Entry.PasskeyField.userHandle) {} else {
            Issue.record("userHandle must be .unprotected")
        }
        if case .unprotected = proto(KDBX.Entry.PasskeyField.privateKeyPEM) {} else {
            Issue.record("PEM must be .unprotected")
        }
    }

    @Test
    func setterOverwritesExistingField() throws {
        var entry = KDBX.Entry(uuid: UUID())
        entry.setPasskeyRelyingParty("first.example")
        entry.setPasskeyRelyingParty("second.example")
        #expect(entry.passkeyRelyingParty == "second.example")
        #expect(entry.strings.filter { $0.key == KDBX.Entry.PasskeyField.relyingParty }.count == 1)
    }

    @Test
    func passkeySurvivesWriteAndReopen() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-passkey", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "123")
        var reader = KDBXReader(data)
        var content = try reader.parse(unlockData: unlock)

        var entry = KDBX.Entry(uuid: UUID())
        entry.setPasskeyRelyingParty("added.example")
        entry.setPasskeyUsername("bob")
        entry.setPasskeyCredentialID(Data([0xDE, 0xAD, 0xBE, 0xEF]))
        entry.setPasskeyUserHandle(Data([0x01]))
        entry.setPasskeyPrivateKeyPEM("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
        content.database.root.group.entries.append(entry)

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("passkey-rt-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }
        let os = OutputStream(toFileAtPath: outPath, append: false)!
        os.open()
        try KDBXWriter(to: os).write(content, unlockData: unlock)
        os.close()

        var reopenReader = KDBXReader(try Data(contentsOf: URL(filePath: outPath)))
        let reopened = try reopenReader.parse(unlockData: unlock)
        var found: KDBX.Entry?
        reopened.database.visitEntries(in: reopened.database.root.group) {
            if $0.passkeyRelyingParty == "added.example" { found = $0 }
        }
        #expect(reopened.parserWarnings.isEmpty)

        let f = try #require(found)
        #expect(f.passkeyCredentialID == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(f.passkeyUserHandle == Data([0x01]))
        #expect(f.passkeyUsername == "bob")
        let pem = try #require(f.passkeyPrivateKeyPEM)
        pem.withRevealedString { #expect($0.contains("AAAA")) }

        // RP and username reopen as .regular (plaintext on disk).
        // Credential ID, user handle, and PEM reopen as .lazyInnerCipher
        // (Protected="True" fields, inner-stream encrypted on disk).
        func proto(_ k: String) -> KDBX.ProtectedString.Value? {
            f.strings.first { $0.key == k }?.value
        }
        if case .regular = proto(KDBX.Entry.PasskeyField.relyingParty) {} else {
            Issue.record("RP should reopen as .regular")
        }
        if case .regular = proto(KDBX.Entry.PasskeyField.username) {} else {
            Issue.record("username should reopen as .regular")
        }
        if case .lazyInnerCipher = proto(KDBX.Entry.PasskeyField.credentialID) {} else {
            Issue.record("credentialID must reopen as .lazyInnerCipher (Protected=True)")
        }
        if case .lazyInnerCipher = proto(KDBX.Entry.PasskeyField.userHandle) {} else {
            Issue.record("userHandle must reopen as .lazyInnerCipher (Protected=True)")
        }
        if case .lazyInnerCipher = proto(KDBX.Entry.PasskeyField.privateKeyPEM) {} else {
            Issue.record("PEM must reopen as .lazyInnerCipher (Protected=True, inner-stream encrypted)")
        }
    }
}
