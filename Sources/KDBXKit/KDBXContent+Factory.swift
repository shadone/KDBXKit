//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBXContent {
    /// Build a fresh, empty vault ready to be passed to `KDBXWriter`.
    ///
    /// Modern defaults: KDBX 4.1 file format, AES-256-CBC main encryption,
    /// gzip compression, ChaCha20 inner stream cipher, Argon2id KDF tuned to
    /// the requested security profile. The masterSalt, encryption nonce,
    /// inner-header key, and KDF salt are filled with CSPRNG bytes.
    ///
    /// - Parameters:
    ///   - databaseName: visible vault name, stored in `Meta.databaseName`.
    ///   - kdf: KDF profile; defaults to `.balanced`. Tune lower for snappy
    ///     unlock at the cost of weaker offline-attack resistance, higher
    ///     for valuable vaults that can afford slower unlock.
    ///   - generator: written into `Meta.generator`; defaults to `"KDBXKit"`.
    static func makeEmpty(
        databaseName: String,
        kdf profile: KDFParameters.Profile = .balanced,
        generator: String = "KDBXKit"
    ) -> KDBXContent {
        let now = Date()
        let rootGroupUUID = UUID()

        let rootGroup = KDBX.Group(
            uuid: rootGroupUUID,
            name: databaseName,
            times: .init(creationTime: now, lastModificationTime: now),
            isExpanded: true
        )

        let meta = KDBX.Meta(
            generator: generator,
            settingsChanged: now,
            databaseName: databaseName,
            databaseNameChanged: now,
            masterKeyChanged: now
        )

        let database = KDBX(
            meta: meta,
            root: KDBX.Root(group: rootGroup, deletedObjects: [])
        )

        // Nonce length matches the chosen main cipher (AES-256-CBC = 16 bytes).
        let header = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: .AES256CBC,
            compressionAlgorithm: .gzip,
            masterSalt: SecureRandom.bytes(32),
            encryptionNonce: SecureRandom.bytes(16),
            kdfParameters: .recommended(profile),
            publicCustomData: [:]
        )

        // ChaCha20 needs 64 bytes of key material per inner-header spec.
        let innerHeader = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: SecureRandom.bytes(64),
            binaryContent: []
        )

        return KDBXContent(database: database, header: header, innerHeader: innerHeader)
    }
}
