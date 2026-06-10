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
    /// gzip compression, ChaCha20 inner stream cipher, and the standard
    /// Argon2id KDF. The masterSalt, encryption nonce, inner-header key,
    /// and KDF salt are filled with CSPRNG bytes.
    ///
    /// - Parameters:
    ///   - databaseName: visible vault name, stored in `Meta.databaseName`.
    ///   - kdf: key-derivation parameters; defaults to
    ///     ``KDFParameters/argon2idDefault()``. Pass your own
    ///     ``KDFParameters`` value to trade unlock latency against
    ///     offline-attack resistance for your deployment.
    ///   - generator: written into `Meta.generator`; defaults to `"KDBXKit"`.
    /// Backwards-compatibility overload taking a pre-tuned
    /// ``KDFParameters/Profile``. Deprecated in 1.3.0 — pass a
    /// ``KDFParameters`` value (e.g. ``KDFParameters/argon2idDefault()``)
    /// instead. The `kdf:` profile has no default here so a no-argument
    /// call resolves unambiguously to the `KDFParameters` overload.
    @available(*, deprecated, message: "Pass a KDFParameters value (e.g. .argon2idDefault()) instead of a Profile.")
    static func makeEmpty(
        databaseName: String,
        kdf profile: KDFParameters.Profile,
        generator: String = "KDBXKit"
    ) -> KDBXContent {
        makeEmpty(databaseName: databaseName, kdf: .recommended(profile), generator: generator)
    }

    static func makeEmpty(
        databaseName: String,
        kdf: KDFParameters = .argon2idDefault(),
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
            masterKeyChanged: now,
            memoryProtection: KDBX.MemoryProtectionConfig(protectPassword: true),
            recycleBinEnabled: true,
            recycleBinUUID: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
            recycleBinChanged: now
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
            kdfParameters: kdf,
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
