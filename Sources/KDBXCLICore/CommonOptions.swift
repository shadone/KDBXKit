//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation

struct CommonOptions: ParsableArguments {
    @Argument(help: "The .kdbx file to open")
    var filepath: String

    @OptionGroup()
    var credentials: CredentialOptions
}
