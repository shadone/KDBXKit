//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

enum AppError: Error, CustomStringConvertible {
    case wrongCredentials
    /// A reader invariant that should be unbreakable was broken. Thrown
    /// instead of fatalError so the CLI exits with a printable message
    /// and a non-zero status rather than a runtime trap.
    case internalError(String)

    var description: String {
        switch self {
        case .wrongCredentials:
            return "The specified master password is not correct."
        case let .internalError(reason):
            return "Internal error: \(reason). Please report this."
        }
    }
}
