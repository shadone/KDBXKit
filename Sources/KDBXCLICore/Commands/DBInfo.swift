//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct Info: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "info",
            abstract: "Inspect a vault's header, KDF parameters, inner header, and validation issues. Prompts for the master password unless --public is given."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @Flag(
            name: .customLong("public"),
            help: "Show only public (unencrypted) header information. No master-password prompt; environment, stdin, and --key-file inputs are ignored. The inner header and validation results are omitted."
        )
        var publicOnly: Bool = false

        mutating func run() throws {
            let kdbx: KDBXReader
            let content: KDBXContent?
            let unlockState: DBInfoSnapshot.UnlockState

            let unlockData: UnlockData? = publicOnly
                ? nil
                : try commonOptions.credentials.resolve(requireUnlock: true)
            switch try read(from: commonOptions.filepath, unlockData: unlockData) {
            case let .noCredentials(kdbxReader):
                kdbx = kdbxReader
                content = nil
                unlockState = .notAttempted

            case let .wrongCredentials(kdbxReader):
                kdbx = kdbxReader
                content = nil
                unlockState = .wrongCredentials

            case let .success(kdbxContent, kdbxReader):
                kdbx = kdbxReader
                content = kdbxContent
                unlockState = .unlocked
            }

            guard let header = kdbx.header else {
                throw AppError.internalError("missing header after parse")
            }

            let snapshot = DBInfoSnapshot(
                header: header,
                unlockState: unlockState,
                blockSizes: kdbx.blockSizes,
                innerHeader: kdbx.innerHeader,
                validationIssues: content?.validate() ?? []
            )

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }
    }
}
