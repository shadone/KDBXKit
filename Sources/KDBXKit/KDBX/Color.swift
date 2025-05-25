//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    /// A hexadecimal CSS color of the form "#RRGGBB". For example, "#FFFF00" is yellow.
    /// An empty string means to use the default value (chosen by the application, suitable
    /// for the current UI).
    enum Color: Sendable, CustomStringConvertible {
        case color(red: UInt8, green: UInt8, blue: UInt8)
        case `default`

        init(stringValue: String) {
            if stringValue.isEmpty {
                self = .default
            } else {
                fatalError("unimplemented")
            }
        }

        var description: String {
            switch self {
            case let .color(red, green, blue):
                return String(format: "#%02X%02X%02X", red, green, blue)
            case .default:
                return ""
            }
        }
    }
}
