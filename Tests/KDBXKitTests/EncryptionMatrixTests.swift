//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Round-trips every combination of (main encryption, KDF, compression)
/// through KDBXWriter → KDBXReader so a regression in one configuration
/// can't slip past the existing fixture-based tests.
@Suite("Encryption × KDF × Compression matrix")
struct EncryptionMatrixTests {
    @Test(
        "Round-trip every combination",
        arguments: [
            (Header.EncryptionAlgorithm.AES256CBC, KDFFlavor.aes, Header.CompressionAlgorithm.none),
            (Header.EncryptionAlgorithm.AES256CBC, KDFFlavor.aes, Header.CompressionAlgorithm.gzip),
            (Header.EncryptionAlgorithm.AES256CBC, KDFFlavor.argon2d, Header.CompressionAlgorithm.none),
            (Header.EncryptionAlgorithm.AES256CBC, KDFFlavor.argon2d, Header.CompressionAlgorithm.gzip),
            (Header.EncryptionAlgorithm.AES256CBC, KDFFlavor.argon2id, Header.CompressionAlgorithm.none),
            (Header.EncryptionAlgorithm.AES256CBC, KDFFlavor.argon2id, Header.CompressionAlgorithm.gzip),
            (Header.EncryptionAlgorithm.ChaCha20, KDFFlavor.aes, Header.CompressionAlgorithm.none),
            (Header.EncryptionAlgorithm.ChaCha20, KDFFlavor.aes, Header.CompressionAlgorithm.gzip),
            (Header.EncryptionAlgorithm.ChaCha20, KDFFlavor.argon2d, Header.CompressionAlgorithm.none),
            (Header.EncryptionAlgorithm.ChaCha20, KDFFlavor.argon2d, Header.CompressionAlgorithm.gzip),
            (Header.EncryptionAlgorithm.ChaCha20, KDFFlavor.argon2id, Header.CompressionAlgorithm.none),
            (Header.EncryptionAlgorithm.ChaCha20, KDFFlavor.argon2id, Header.CompressionAlgorithm.gzip),
        ]
    )
    func roundtrip(
        encryption: Header.EncryptionAlgorithm,
        kdf: KDFFlavor,
        compression: Header.CompressionAlgorithm
    ) throws {
        let content = makeVault(encryption: encryption, kdf: kdf, compression: compression)
        let unlock = UnlockData(masterPassword: "matrix-test-pw")

        let stream = OutputStream(toMemory: ())
        stream.open()
        try KDBXWriter(to: stream).write(content, unlockData: unlock)
        let bytes = stream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        stream.close()

        let reopened = try KDBXReader.parse(bytes, unlockData: unlock)

        #expect(reopened.header.encryptionAlgorithm == encryption)
        #expect(reopened.header.compressionAlgorithm == compression)
        #expect(reopened.database.meta.databaseName == "Matrix")
    }

    enum KDFFlavor: Sendable, CustomStringConvertible {
        case aes, argon2d, argon2id
        var description: String {
            switch self {
            case .aes: return "AES-KDF"
            case .argon2d: return "Argon2d"
            case .argon2id: return "Argon2id"
            }
        }
    }

    private func makeVault(
        encryption: Header.EncryptionAlgorithm,
        kdf: KDFFlavor,
        compression: Header.CompressionAlgorithm
    ) -> KDBXContent {
        // Match nonce length to cipher; AES-256-CBC = 16, ChaCha20 = 12.
        let nonceLength = encryption == .AES256CBC ? 16 : 12

        // Use minimal KDF parameters so the matrix runs in seconds, not minutes.
        let kdfParameters: KDFParameters
        switch kdf {
        case .aes:
            kdfParameters = .aes(.init(salt: SecureRandom.bytes(32), rounds: 100), additional: [:])
        case .argon2d:
            kdfParameters = .argon2d(
                .init(
                    version: .v1_3,
                    salt: SecureRandom.bytes(32),
                    iterations: 1,
                    memory: 8 * 1024 * 1024,
                    parallelism: 2
                ),
                additional: [:]
            )
        case .argon2id:
            kdfParameters = .argon2id(
                .init(
                    version: .v1_3,
                    salt: SecureRandom.bytes(32),
                    iterations: 1,
                    memory: 8 * 1024 * 1024,
                    parallelism: 2
                ),
                additional: [:]
            )
        }

        let now = Date()
        let rootGroup = KDBX.Group(
            uuid: UUID(),
            name: "Matrix",
            times: .init(creationTime: now, lastModificationTime: now),
            isExpanded: true
        )
        let meta = KDBX.Meta(
            generator: "KDBXKit",
            databaseName: "Matrix",
            databaseNameChanged: now,
            masterKeyChanged: now
        )

        return KDBXContent(
            database: KDBX(meta: meta, root: KDBX.Root(group: rootGroup, deletedObjects: [])),
            header: Header(
                formatVersion: .v4_1,
                encryptionAlgorithm: encryption,
                compressionAlgorithm: compression,
                masterSalt: SecureRandom.bytes(32),
                encryptionNonce: SecureRandom.bytes(nonceLength),
                kdfParameters: kdfParameters,
                publicCustomData: [:]
            ),
            innerHeader: InnerHeader(
                encryptionAlgorithm: .ChaCha20,
                encryptionKey: SecureRandom.bytes(64),
                binaryContent: []
            )
        )
    }
}
