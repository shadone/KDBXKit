//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public struct ValidationFailure: Sendable, Equatable {
    public enum Level: CustomStringConvertible, Sendable {
        case warning
        case error

        public var description: String {
            switch self {
            case .warning:
                return "Warning"
            case .error:
                return "Error"
            }
        }
    }

    public let level: Level
    public let message: String

    static func warning(_ message: String) -> ValidationFailure {
        .init(level: .warning, message: message)
    }

    static func error(_ message: String) -> ValidationFailure {
        .init(level: .error, message: message)
    }
}
