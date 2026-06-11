//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct Migrate: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "migrate",
            abstract:
            "Migrate a legacy KDBX 3.1 vault to KDBX 4.1. " +
                "Upgrades the KDF to Argon2id by default (the modern KeePassXC default). " +
                "No-op on files that are already KDBX 4.x."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @Option(
            name: .customLong("profile"),
            help: ArgumentHelp(
                "Argon2id profile applied as part of the migration. Ignored when --keep-kdf is set.",
                valueName: "fast|balanced|paranoid"
            )
        )
        var profile: KDFProfile = .balanced

        @Flag(
            name: .customLong("keep-kdf"),
            help: ArgumentHelp(
                "Preserve the source vault's KDF (AES-KDF) instead of upgrading to Argon2id. " +
                    "The format is still migrated to 4.1; only the KDF is left alone."
            )
        )
        var keepKDF: Bool = false

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            // No-op on files that are already 4.x. Print a status
            // line and exit cleanly so the command is safe to run
            // over a directory of mixed-vintage vaults.
            guard content.header.formatVersion.isLegacy3x else {
                print("\(commonOptions.filepath): already KDBX \(content.header.formatVersion); nothing to migrate.")
                return
            }

            var updated = content
            if !keepKDF {
                updated.upgradeToArgon2id(to: profile.kdfParameters)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            // The summary is formatted from the in-memory content the
            // writer just serialized; writeAtomically has either fully
            // replaced the file with those bytes or thrown.
            let summary: String
            if keepKDF {
                summary = "migrated KDBX \(content.header.formatVersion) → 4.1 (KDF unchanged)"
            } else {
                summary = "migrated KDBX \(content.header.formatVersion) → 4.1; KDF upgraded to Argon2id (\(profile.rawValue))"
            }
            print("\(commonOptions.filepath): \(summary).")
        }
    }
}
