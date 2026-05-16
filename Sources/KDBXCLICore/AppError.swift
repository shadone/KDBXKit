//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

enum AppError: Error, CustomStringConvertible {
    case wrongCredentials

    var description: String {
        switch self {
        case .wrongCredentials:
            return "The specified master password is not correct."
        }
    }
}
