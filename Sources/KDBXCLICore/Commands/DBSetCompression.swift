//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct SetCompression: ParsableCommand {
        enum Mode: String, ExpressibleByArgument, CaseIterable {
            case gzip
            case none
        }

        static let configuration = CommandConfiguration(
            commandName: "set-compression",
            abstract: "Enable or disable gzip compression for the inner payload."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @Argument(help: ArgumentHelp("Compression mode.", valueName: "gzip|none"))
        var mode: Mode

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let newMode: Header.CompressionAlgorithm
            switch mode {
            case .gzip: newMode = .gzip
            case .none: newMode = .none
            }
            var updated = content
            updated.header = content.header.with(compressionAlgorithm: newMode)

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )
            print("Compression updated to \(mode.rawValue): \(commonOptions.filepath)")
        }
    }
}
