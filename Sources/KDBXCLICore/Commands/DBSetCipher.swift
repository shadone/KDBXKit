//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct SetCipher: ParsableCommand {
        enum CipherOption: String, ExpressibleByArgument, CaseIterable {
            case chacha20
            case aes256
        }

        static let configuration = CommandConfiguration(
            commandName: "set-cipher",
            abstract: "Change the main payload cipher. KDBXKit supports AES-256-CBC and ChaCha20."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @Argument(help: ArgumentHelp("New cipher.", valueName: "chacha20|aes256"))
        var cipher: CipherOption

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let newAlgo: Header.EncryptionAlgorithm
            switch cipher {
            case .chacha20: newAlgo = .ChaCha20
            case .aes256: newAlgo = .AES256CBC
            }
            var updated = content
            updated.header = content.header.with(encryptionAlgorithm: newAlgo)
            // KDBXWriter.regenerateSalts (default-on) re-mints `encryptionNonce`
            // at the correct length for the chosen cipher.

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )
            print("Cipher updated to \(cipher.rawValue): \(commonOptions.filepath)")
        }
    }
}
