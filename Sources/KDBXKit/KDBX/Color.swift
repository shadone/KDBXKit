//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    /// A hexadecimal CSS color of the form "#RRGGBB". For example, "#FFFF00" is yellow.
    /// An empty string means to use the default value (chosen by the application, suitable
    /// for the current UI).
    public enum Color: Sendable, CustomStringConvertible, Equatable {
        case color(red: UInt8, green: UInt8, blue: UInt8)
        case `default`

        init?(stringValue: String) {
            if stringValue.isEmpty {
                self = .default
            } else {
                guard stringValue.hasPrefix("#"), stringValue.count == 7 else {
                    assertionFailure("Invalid color input: \(stringValue)")
                    return nil
                }
                let hexString = String(stringValue.dropFirst())
                if let hexValue = UInt32(hexString, radix: 16) {
                    let red = UInt8((hexValue >> 16) & 0xFF)
                    let green = UInt8((hexValue >> 8) & 0xFF)
                    let blue = UInt8(hexValue & 0xFF)
                    self = .color(red: red, green: green, blue: blue)
                } else {
                    return nil
                }
            }
        }

        public var description: String {
            switch self {
            case let .color(red, green, blue):
                return String(format: "#%02X%02X%02X", red, green, blue)
            case .default:
                return ""
            }
        }
    }
}
