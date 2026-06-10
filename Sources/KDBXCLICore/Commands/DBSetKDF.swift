//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct SetKDF: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "set-kdf",
            abstract: "Change the vault's KDF profile (fast / balanced / paranoid). Argon2id under the hood."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @Option(
            name: .customLong("profile"),
            help: ArgumentHelp(
                "Argon2id profile: fast (snappier unlock, weaker resistance), balanced (default), paranoid (highest resistance, slow unlock).",
                valueName: "fast|balanced|paranoid"
            )
        )
        var profile: KDFProfile = .balanced

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            var updated = content
            updated.header = content.header.with(kdfParameters: profile.kdfParameters)

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )
            print("KDF profile updated to \(profile.rawValue): \(commonOptions.filepath)")
        }
    }
}
