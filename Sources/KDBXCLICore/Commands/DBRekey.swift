//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct Rekey: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rekey",
            abstract: "Change a vault's master password and/or key file. KDF parameters are preserved; salts are regenerated."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var newCredentialOptions: NewCredentialOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        mutating func run() throws {
            let oldUnlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: oldUnlock)
            else {
                throw AppError.wrongCredentials
            }

            let newUnlock = try newCredentialOptions.resolve(
                oldUsedStdin: commonOptions.credentials.passwordFromStdin
            )

            try VaultWriting.writeAtomically(
                content: content,
                unlockData: newUnlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Rekey complete: \(commonOptions.filepath)")
        }
    }
}
