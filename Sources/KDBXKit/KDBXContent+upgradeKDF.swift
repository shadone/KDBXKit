//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBXContent {
    /// Replace the file's key-derivation function.
    ///
    /// Used during a save when the caller wants to switch the KDF
    /// without changing the master password — typically as part of a
    /// KDBX 3.x → 4.1 migration, where the source file's AES-KDF is
    /// upgraded to a memory-hard modern KDF (Argon2id). The user
    /// types the same password they always have; the next
    /// ``KDBXWriter/write(_:unlockData:regenerateSalts:)`` derives the
    /// new unlock key against the new KDF parameters automatically.
    ///
    /// This is a pure header mutation — no re-encryption happens
    /// here. The next save is where the new KDF parameters actually
    /// take effect on disk.
    ///
    /// The salt embedded in `kdf` is treated as fresh; the writer's
    /// regenerate-salts pass will replace it again on save (the spec
    /// requires fresh salts per save anyway).
    mutating func upgradeKDF(to kdf: KDFParameters) {
        header = Header(
            formatVersion: header.formatVersion,
            encryptionAlgorithm: header.encryptionAlgorithm,
            compressionAlgorithm: header.compressionAlgorithm,
            masterSalt: header.masterSalt,
            encryptionNonce: header.encryptionNonce,
            kdfParameters: kdf,
            publicCustomData: header.publicCustomData
        )
    }

    /// Convenience for the most common upgrade: switch to Argon2id at
    /// a recommended security level.
    ///
    /// This is the right call to make when migrating a KDBX 3.x file
    /// (which can only use AES-KDF) to 4.1 — Argon2id is memory-hard
    /// and the modern KeePassXC default. AES-KDF predates the
    /// memory-hard KDF era and is significantly cheaper for an
    /// attacker with custom hardware.
    ///
    /// The default ``KDFParameters/Profile/balanced`` profile matches
    /// modern KeePassXC defaults (~1.5 s unlock on contemporary Apple
    /// Silicon). Pass ``KDFParameters/Profile/fast`` for vaults
    /// unlocked often (menubar popover, autofill) or
    /// ``KDFParameters/Profile/paranoid`` for high-value targets.
    ///
    /// The library does not call this automatically as part of save —
    /// preserving the source file's KDF on round-trip is the default
    /// because it produces the smallest, most reversible diff. Apps
    /// that want the upgrade (and Passie does) invoke this explicitly
    /// after observing ``legacyFormatNotice``.
    mutating func upgradeToArgon2id(profile: KDFParameters.Profile = .balanced) {
        upgradeKDF(to: .recommended(profile))
    }
}
