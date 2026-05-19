//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    /// An RGB color used for UI hints — vault-level accent
    /// (``Meta/color``) and per-entry foreground / background
    /// (``Entry/foregroundColor`` / ``Entry/backgroundColor``).
    ///
    /// On disk the color is serialized as a CSS-style hex string
    /// `"#RRGGBB"` (e.g. `"#FFFF00"` for yellow). An empty string is
    /// the KDBX spec's way of saying "no preference, let the client
    /// pick" and decodes to ``default``.
    ///
    /// Not security-relevant; UI hint only.
    enum Color: Sendable, CustomStringConvertible, Equatable {
        /// An explicit RGB color.
        case color(red: UInt8, green: UInt8, blue: UInt8)

        /// "No color preference, let the client pick a sensible
        /// default for the current UI." Serialized as an empty
        /// string.
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

        /// CSS-hex form: `"#RRGGBB"` for ``color(red:green:blue:)``,
        /// empty string for ``default``. Matches the on-disk
        /// serialization used by KDBX.
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
