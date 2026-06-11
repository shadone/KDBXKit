//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// The KDBX 3.1 `<Meta><Binaries>` pool has two failure modes the reader
/// must handle: protected pool entries are XOR'd with the inner keystream
/// (consumed before the entry passwords, since Meta precedes Root), and
/// entry `Ref` attributes carry the on-disk pool ID — which only equals
/// the array index when IDs are contiguous from zero.
@Suite("KDBX 3.1 Meta/Binaries pool")
struct Legacy3xPoolTests {
    private func keystream() -> KeystreamSource {
        KeystreamSource(
            algorithm: .salsa20,
            key: SecureBytes(Data(repeating: 9, count: 32)),
            nonce: Data([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])
        )
    }

    private func reader(_ body: String, _ ks: KeystreamSource) throws -> XMLDocumentReader {
        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <KeePassFile>\(body)</KeePassFile>
            """
        return try XMLDocumentReader(xmlDocument: xml, keystreamSource: ks, dateFormat: .iso8601)
    }

    @Test("Entry Ref attributes are remapped from on-disk ID to pool index")
    func nonContiguousIDsRemap() throws {
        // Pool IDs {0, 2, 3} (KeePass would write 0,1,2 — but a hand-built
        // or lax producer can leave gaps). Distinct contents so the
        // mapping is observable.
        let a = Data("AAA".utf8).base64EncodedString()
        let b = Data("BBBB".utf8).base64EncodedString()
        let c = Data("CCCCC".utf8).base64EncodedString()
        let ks = keystream()
        let r = try reader("""
            <Meta><Binaries>\
            <Binary ID="0">\(a)</Binary>\
            <Binary ID="2">\(b)</Binary>\
            <Binary ID="3">\(c)</Binary>\
            </Binaries></Meta>\
            <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
            <Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
            <Binary><Key>two.bin</Key><Value Ref="2"/></Binary>\
            <Binary><Key>three.bin</Key><Value Ref="3"/></Binary>\
            </Entry></Group></Root>
            """, ks)
        let db = try r.parse()

        // Pool is positional, sorted by ID: [AAA, BBBB, CCCCC].
        let pool = r.inlineBinaryPool
        #expect(pool.map(\.data) == [Data("AAA".utf8), Data("BBBB".utf8), Data("CCCCC".utf8)])

        // Ref="2" (ID 2 = "BBBB") must now point to index 1, Ref="3" to 2.
        let entry = try #require(db.root.group.entries.first)
        func refIndex(_ key: String) throws -> UInt32 {
            guard case let .ref(idx) = try #require(entry.binaries.first(where: { $0.key == key })).value else {
                Issue.record("\(key) is not a ref")
                return .max
            }
            return idx
        }
        #expect(try refIndex("two.bin") == 1)
        #expect(try refIndex("three.bin") == 2)
        // Resolving through the pool yields the right bytes.
        #expect(pool[Int(try refIndex("two.bin"))].data == Data("BBBB".utf8))
        #expect(pool[Int(try refIndex("three.bin"))].data == Data("CCCCC".utf8))
    }

    @Test("Duplicate pool IDs are rejected")
    func duplicateIDsThrow() throws {
        let a = Data("AAA".utf8).base64EncodedString()
        let r = try reader("""
            <Meta><Binaries>\
            <Binary ID="0">\(a)</Binary>\
            <Binary ID="0">\(a)</Binary>\
            </Binaries></Meta>\
            <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID></Group></Root>
            """, keystream())
        #expect(throws: XMLDocumentReader.Error.self) {
            _ = try r.parse()
        }
    }

    @Test("Protected pool binary is keystream-decrypted and consumes the stream before entries")
    func protectedPoolDecryptedAndOrdered() throws {
        let ks = keystream()
        let poolPlain = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let passwordPlain = Data("after-pool".utf8)

        // Document order: pool binary first, then the entry password.
        let poolCipher = ks.decrypt(ciphertext: poolPlain, at: 0).toData()
        let passwordCipher = ks.decrypt(ciphertext: passwordPlain, at: poolPlain.count).toData()

        let r = try reader("""
            <Meta><Binaries>\
            <Binary ID="0" Protected="True">\(poolCipher.base64EncodedString())</Binary>\
            </Binaries></Meta>\
            <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
            <Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>\
            <String><Key>Password</Key><Value Protected="True">\(passwordCipher.base64EncodedString())</Value></String>\
            </Entry></Group></Root>
            """, ks)
        let db = try r.parse()

        // The pool entry decrypts to plaintext.
        #expect(r.inlineBinaryPool.first?.data == poolPlain)
        // And the password AFTER it decrypts correctly only because the
        // pool binary advanced the shared keystream cursor.
        let entry = try #require(db.root.group.entries.first)
        let password = try #require(entry.strings.first(where: { $0.key == "Password" }))
        #expect(password.value.revealedString == "after-pool")
    }
}
