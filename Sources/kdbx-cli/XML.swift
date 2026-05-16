//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

struct XML: ParsableCommand {
    @OptionGroup()
    var commonOptions: CommonOptions

    mutating func run() throws {
        let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
        guard
            case let .success(_, kdbx) = try read(from: commonOptions.filepath, unlockData: unlockData)
        else {
            throw AppError.invalidUnlockData
        }

        guard let xmlDocument = kdbx.xmlDocument else {
            preconditionFailure()
        }

        print(xmlDocument)
    }
}
