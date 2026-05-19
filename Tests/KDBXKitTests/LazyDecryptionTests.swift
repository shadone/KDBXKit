//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// C-7 invariant: after parsing a KDBX file, protected entry strings
/// (passwords, TOTP seeds) are NOT plaintext in memory. They're held
/// as `.lazyInnerCipher` ciphertext + a `KeystreamSource` reference;
/// plaintext only materializes when a caller explicitly asks via
/// `.bytes` / `.withRevealedString`.
@Suite("Lazy per-entry decryption (C-7)")
struct LazyDecryptionTests {
    @Test("After parse, every protected field is .lazyInnerCipher (not eagerly decrypted)")
    func protectedFieldsAreLazyAfterParse() throws {
        let canary = "MEMORY-DWELL-CANARY-32-BYTES-XYZQ"
        let bytes = try makeVaultWithPassword(canary)

        let content = try KDBXReader.parse(bytes, unlockData: UnlockData(masterPassword: "matrix-test-pw"))

        var seenProtected = 0
        var seenEager = 0
        for entry in content.database.allEntries {
            for protectedString in entry.strings {
                if case .lazyInnerCipher = protectedString.value {
                    seenProtected += 1
                } else if case .unprotected = protectedString.value {
                    seenEager += 1
                }
            }
        }

        #expect(seenProtected > 0, "Reader produced no .lazyInnerCipher values — the lazy refactor regressed")
        #expect(seenEager == 0, "Reader still produces eager .unprotected values for protected fields")
    }

    @Test("Lazy ciphertext bytes do NOT contain the plaintext canary")
    func ciphertextDoesNotLeakPlaintext() throws {
        let canary = "MEMORY-DWELL-CANARY-32-BYTES-XYZQ"
        let canaryUtf8 = canary.data(using: .utf8)!
        let bytes = try makeVaultWithPassword(canary)
        let content = try KDBXReader.parse(bytes, unlockData: UnlockData(masterPassword: "matrix-test-pw"))

        for entry in content.database.allEntries {
            for protectedString in entry.strings {
                if case let .lazyInnerCipher(ciphertext, _, _) = protectedString.value {
                    let containsCanary = ciphertext.range(of: canaryUtf8) != nil
                    #expect(
                        !containsCanary,
                        "Lazy ciphertext contains canary plaintext — the inner cipher must be wrong"
                    )
                }
            }
        }
    }

    @Test("Explicit `.withRevealedString` materializes the canary correctly")
    func lazyDecryptProducesCorrectPlaintext() throws {
        let canary = "MEMORY-DWELL-CANARY-32-BYTES-XYZQ"
        let bytes = try makeVaultWithPassword(canary)
        let content = try KDBXReader.parse(bytes, unlockData: UnlockData(masterPassword: "matrix-test-pw"))

        var matched = false
        for entry in content.database.allEntries {
            for protectedString in entry.strings where protectedString.key == "Password" {
                protectedString.value.withRevealedString { plaintext in
                    if plaintext == canary {
                        matched = true
                    }
                }
            }
        }
        #expect(matched, "Lazy decrypt did not produce the canary — round-trip is broken")
    }

    // MARK: - Helpers

    /// Build a minimal vault with one entry whose Password is the
    /// given canary string, write it to bytes, and return the bytes.
    private func makeVaultWithPassword(_ canary: String) throws -> Data {
        let now = Date()
        let entry = KDBX.Entry(
            uuid: UUID(),
            times: .init(creationTime: now, lastModificationTime: now),
            strings: [
                KDBX.ProtectedString(key: "Title", value: .regular("Canary Entry")),
                KDBX.ProtectedString(key: "UserName", value: .regular("user@example.com")),
                KDBX.ProtectedString(key: "Password", value: .unprotected(canary)),
                KDBX.ProtectedString(key: "URL", value: .regular("")),
                KDBX.ProtectedString(key: "Notes", value: .regular("")),
            ]
        )
        let rootGroup = KDBX.Group(
            uuid: UUID(),
            name: "Root",
            times: .init(creationTime: now, lastModificationTime: now),
            isExpanded: true,
            entries: [entry]
        )
        let meta = KDBX.Meta(
            generator: "KDBXKit",
            databaseName: "Canary",
            databaseNameChanged: now,
            masterKeyChanged: now
        )

        let content = KDBXContent(
            database: KDBX(meta: meta, root: KDBX.Root(group: rootGroup, deletedObjects: [])),
            header: Header(
                formatVersion: .v4_1,
                encryptionAlgorithm: .ChaCha20,
                compressionAlgorithm: .gzip,
                masterSalt: SecureRandom.bytes(32),
                encryptionNonce: SecureRandom.bytes(12),
                kdfParameters: .argon2id(
                    .init(
                        version: .v1_3,
                        salt: SecureRandom.bytes(32),
                        iterations: 1,
                        memory: 8 * 1024 * 1024,
                        parallelism: 2
                    ),
                    additional: [:]
                ),
                publicCustomData: [:]
            ),
            innerHeader: InnerHeader(
                encryptionAlgorithm: .ChaCha20,
                encryptionKey: SecureRandom.bytes(64),
                binaryContent: []
            )
        )

        let stream = OutputStream(toMemory: ())
        stream.open()
        try KDBXWriter(to: stream).write(content, unlockData: UnlockData(masterPassword: "matrix-test-pw"))
        let bytes = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        stream.close()
        return bytes
    }
}

private extension KDBX {
    /// Walk the database tree and yield every entry — used by the C-7
    /// invariant tests so they can sweep across the whole vault.
    var allEntries: [Entry] {
        var result: [Entry] = []
        collectEntries(in: root.group, into: &result)
        return result
    }

    private func collectEntries(in group: Group, into result: inout [Entry]) {
        result.append(contentsOf: group.entries)
        for child in group.groups {
            collectEntries(in: child, into: &result)
        }
    }
}
