//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct XML: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "xml",
            abstract: "Decrypt the vault and print the inner XML document to stdout."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            switch try read(
                from: commonOptions.filepath,
                unlockData: unlockData,
                retainsXMLForDiagnostics: true
            ) {
            case .noCredentials, .wrongCredentials:
                throw AppError.wrongCredentials

            case let .success(_, kdbx):
                guard let xmlDocument = kdbx.xmlDocument else {
                    throw AppError.internalError("XML document missing after parse with retainsXMLForDiagnostics: true")
                }
                print(xmlDocument)
            }
        }
    }
}
