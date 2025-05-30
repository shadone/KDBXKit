//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The value type of the ``VariantDictionary``
public enum VariantDictionaryValue: Sendable, Equatable {
    case uint32(UInt32)
    case uint64(UInt64)
    case boolean(Bool)
    case int32(Int32)
    case int64(Int64)
    case string(String)
    case bytes(Data)
}

/// A name-value dictionary, where the name is a string and the type of the value depends on the item.
public typealias VariantDictionary = [String: VariantDictionaryValue]

extension VariantDictionary {
    struct FormatVersion: RawRepresentable, Equatable {
        /// The high byte is the major version.
        ///
        /// It is critical, i.e. an application must refuse to load the file if the major version is unsupported.
        let major: UInt8

        /// The low byte is the minor version.
        ///
        /// It can be ignored, but when encountering an unsupported value type, a confirmation/warning should be displayed or loading should fail.
        let minor: UInt8

        /// The value is in **little endian**.
        var rawValue: UInt16 {
            UInt16(major) << 8 | UInt16(minor)
        }

        init(major: UInt8, minor: UInt8) {
            self.major = major
            self.minor = minor
        }

        /// - parameter rawValue: the value should be in **little endian**
        init(rawValue: UInt16) {
            // The high byte is the major version
            major = UInt8(rawValue >> 8)
            // The low byte is the minor version
            minor = UInt8(rawValue & 0xFF)
        }

        static let v1_0: FormatVersion = .init(major: 1, minor: 0)
    }
}
