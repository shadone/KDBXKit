//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation
import Testing
@testable import KDBXKit

/// Validates that the `UnlockData(masterPassword:, keyFile:)` and
/// `UnlockData(keyFile:)` initializers actually produce different unlock
/// keys (so they round-trip distinct ciphertexts), and that mismatched
/// credentials are rejected.
@Suite("Key-file unlock")
struct KeyFileTests {

    @Test("Password + key file round-trips")
    func passwordAndKeyFile() throws {
        let content = KDBXContent.makeEmpty(databaseName: "WithKeyFile", kdf: .fast)
        let keyFile = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let unlock = UnlockData(masterPassword: "pw", keyFile: keyFile)

        let bytes = try writeToMemory(content, unlockData: unlock)
        let reopened = try KDBXReader.parse(bytes, unlockData: unlock)
        #expect(reopened.database.meta.databaseName == "WithKeyFile")
    }

    @Test("Key file alone (no password) round-trips")
    func keyFileOnly() throws {
        let content = KDBXContent.makeEmpty(databaseName: "KeyOnly", kdf: .fast)
        let keyFile = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let unlock = UnlockData(keyFile: keyFile)

        let bytes = try writeToMemory(content, unlockData: unlock)
        let reopened = try KDBXReader.parse(bytes, unlockData: unlock)
        #expect(reopened.database.meta.databaseName == "KeyOnly")
    }

    // MARK: Keyfile normalization (KDBX spec section "Key file")
    //
    // The user-provided keyfile bytes are reduced to a 32-byte contribution
    // before being mixed into the unlock-key derivation:
    //   - exactly 32 bytes  → use raw
    //   - exactly 64 hex    → decode hex → 32 bytes
    //   - anything else     → SHA-256(file)
    // Until we added this normalization the reader could only round-trip the
    // first case with other implementations.

    @Test("Keyfile normalization: 32 raw bytes passes through unchanged")
    func normalize_raw32() {
        let raw = Data((0..<32).map { UInt8($0) })
        #expect(UnlockData.normalizeKeyFile(raw) == raw)
    }

    @Test("Keyfile normalization: 64 ASCII hex decodes to 32 bytes")
    func normalize_hex64() {
        // Mixed case hex; expect 0x00..0x1F.
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F"
        let decoded = UnlockData.normalizeKeyFile(Data(hex.utf8))
        #expect(decoded == Data((0..<32).map { UInt8($0) }))
    }

    @Test("Keyfile normalization: 64 bytes that aren't valid hex fall back to SHA-256")
    func normalize_64nonHex() {
        // 64 bytes of 0xFF — not valid ASCII hex.
        let blob = Data(repeating: 0xFF, count: 64)
        let normalized = UnlockData.normalizeKeyFile(blob)
        #expect(normalized == Data(SHA256.hash(data: blob)))
    }

    @Test("Keyfile normalization: arbitrary binary file is SHA-256-hashed")
    func normalize_arbitraryBinary() {
        let blob = Data((0..<200).map { UInt8($0 & 0xFF) })
        let normalized = UnlockData.normalizeKeyFile(blob)
        #expect(normalized == Data(SHA256.hash(data: blob)))
    }

    @Test("Keyfile normalization: v1 XML keyfile (hex inside <Data>) parses to 32 bytes")
    func normalize_xmlV1Hex() {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeyFile>
            <Meta><Version>1.0</Version></Meta>
            <Key>
                <Data>000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F</Data>
            </Key>
        </KeyFile>
        """
        let normalized = UnlockData.normalizeKeyFile(Data(xml.utf8))
        #expect(normalized == Data((0..<32).map { UInt8($0) }))
    }

    @Test("Keyfile normalization: v2 XML keyfile (base64 + Hash attribute) parses to 32 bytes")
    func normalize_xmlV2Base64() {
        // base64 of bytes 0x00..0x1F:
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeyFile>
            <Meta><Version>2.0</Version></Meta>
            <Key>
                <Data Hash="50E03C97">AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</Data>
            </Key>
        </KeyFile>
        """
        let normalized = UnlockData.normalizeKeyFile(Data(xml.utf8))
        #expect(normalized == Data((0..<32).map { UInt8($0) }))
    }

    @Test("Keyfile normalization: malformed XML keyfile falls through to SHA-256 fallback")
    func normalize_malformedXMLFallsThrough() {
        // Looks like XML (has `<KeyFile`) but the Data element is bogus.
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <KeyFile>
            <Key>
                <Data>not-valid-hex-or-base64-and-not-32-chars-long</Data>
            </Key>
        </KeyFile>
        """
        let blob = Data(xml.utf8)
        let normalized = UnlockData.normalizeKeyFile(blob)
        // Falls through to SHA-256(file) — a defensive choice rather than
        // throwing; produces a stable-but-different unlock key for
        // unrecognized shapes.
        #expect(normalized == Data(SHA256.hash(data: blob)))
    }

    @Test("Real KeePassXC-generated 128-byte binary keyfile unlocks the matching db")
    func realKeyFileFromKeePassXC() throws {
        // Built via `keepassxc-cli db-edit --set-key-file …` — the CLI
        // auto-generated a 128-byte binary keyfile (KeePassXC's default
        // shape). Without normalize-to-32 our reader rejected this as
        // .wrongCredentials.
        let dbPath = Bundle.module.path(forResource: "Resources/kpxc-keyfile", ofType: "kdbx")!
        let kfPath = Bundle.module.path(forResource: "Resources/kpxc-keyfile", ofType: "key")!
        let data = try Data(contentsOf: URL(filePath: dbPath))
        let keyFile = try Data(contentsOf: URL(filePath: kfPath))
        #expect(keyFile.count == 128)

        let content = try KDBXReader.parse(
            data,
            unlockData: .init(masterPassword: "123", keyFile: keyFile)
        )
        #expect(content.database.meta.databaseName != nil)
    }

    @Test("Right password but wrong key file is rejected")
    func wrongKeyFile() throws {
        let content = KDBXContent.makeEmpty(databaseName: "X", kdf: .fast)
        let keyA = Data(repeating: 0xAA, count: 64)
        let keyB = Data(repeating: 0xBB, count: 64)

        let bytes = try writeToMemory(content, unlockData: .init(masterPassword: "pw", keyFile: keyA))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(bytes, unlockData: .init(masterPassword: "pw", keyFile: keyB))
        }
    }

    @Test("Password-only file rejects password+keyfile unlock")
    func componentsMustMatch() throws {
        let content = KDBXContent.makeEmpty(databaseName: "X", kdf: .fast)
        let keyFile = Data(repeating: 0xAA, count: 64)
        let bytes = try writeToMemory(content, unlockData: .init(masterPassword: "pw"))

        #expect(throws: KDBXReader.Error.wrongCredentials) {
            _ = try KDBXReader.parse(bytes, unlockData: .init(masterPassword: "pw", keyFile: keyFile))
        }
    }

    private func writeToMemory(_ content: KDBXContent, unlockData: UnlockData) throws -> Data {
        let stream = OutputStream(toMemory: ())
        stream.open()
        try KDBXWriter(to: stream).write(content, unlockData: unlockData)
        let bytes = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        stream.close()
        return bytes
    }
}
