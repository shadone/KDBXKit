//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct Create: ParsableCommand {
        enum CipherArg: String, ExpressibleByArgument, CaseIterable {
            case chacha20
            case aes256
        }

        static let configuration = CommandConfiguration(
            commandName: "create",
            abstract: "Create a fresh vault. Refuses to overwrite an existing file unless --force."
        )

        @OptionGroup()
        var newCredentialOptions: NewCredentialOptions

        @Argument(help: "Destination path for the new .kdbx file.")
        var filepath: String

        @Option(name: .customLong("name"), help: "Display name stored in Meta.databaseName. Defaults to the file's basename without extension.")
        var name: String?

        @Option(
            name: .customLong("kdf-profile"),
            help: ArgumentHelp(
                "Argon2id profile.",
                valueName: "fast|balanced|paranoid"
            )
        )
        var kdfProfile: KDFProfile = .balanced

        @Option(
            name: .customLong("cipher"),
            help: ArgumentHelp(
                "Main payload cipher.",
                valueName: "chacha20|aes256"
            )
        )
        var cipher: CipherArg = .chacha20

        @Flag(name: .customLong("no-compression"), help: "Disable gzip on the inner payload.")
        var noCompression: Bool = false

        @Flag(name: .customLong("force"), help: "Overwrite the file at <path> if it exists.")
        var force: Bool = false

        mutating func run() throws {
            let url = URL(filePath: filepath)
            if FileManager.default.fileExists(atPath: url.path), !force {
                throw CreateError.fileExists(filepath)
            }

            let unlock = try newCredentialOptions.resolve(oldUsedStdin: false)
            let displayName = name ?? url.deletingPathExtension().lastPathComponent

            var content = KDBXContent.makeEmpty(databaseName: displayName, kdf: kdfProfile.kdfParameters)

            let cipherAlgo: Header.EncryptionAlgorithm
            switch cipher {
            case .chacha20: cipherAlgo = .ChaCha20
            case .aes256: cipherAlgo = .AES256CBC
            }
            let compression: Header.CompressionAlgorithm = noCompression ? .none : .gzip

            content.header = content.header
                .with(encryptionAlgorithm: cipherAlgo)
                .with(compressionAlgorithm: compression)

            // `--force` overwriting an existing vault is destructive; auto-bak
            // so a typo is recoverable. (Backup of a non-existent file is a
            // no-op inside AtomicFileWriter.)
            try VaultWriting.writeAtomically(
                content: content,
                unlockData: unlock,
                to: url,
                backup: force
            )
            print("Created \(url.path) (\(cipher.rawValue), \(compression == .gzip ? "gzip" : "no compression"), kdf=\(kdfProfile.rawValue))")
        }
    }
}

enum CreateError: Error, CustomStringConvertible {
    case fileExists(String)

    var description: String {
        switch self {
        case let .fileExists(path):
            return "File already exists: \(path). Pass --force to overwrite (existing content will go to \(path).bak)."
        }
    }
}
