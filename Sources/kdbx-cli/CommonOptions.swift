//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

struct CommonOptions: ParsableCommand {
    @Argument(help: "The .kdbx file to open")
    var filepath: String

    @Argument(help: "The master password to use")
    var masterPassword: String?

    var unlockData: UnlockData? {
        if let masterPassword {
            return .init(masterPassword: masterPassword)
        }
        return nil
    }
}
