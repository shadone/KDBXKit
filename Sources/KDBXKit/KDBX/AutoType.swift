//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    /// https://keepass.info/help/base/autotype.html
    struct AutoType: Sendable {
        //  This is actually unordered except for the Association child elements, where the order matters.

        var enabled: Bool?

        enum DataTransferObfuscation: Int32, Sendable {
            /// No obfuscation.
            case noObfuscation = 0

            /// Two-channel auto-type obfuscation. https://keepass.info/help/v2/autotype_obfuscation.html
            case twoChannelObfuscation = 1
        }

        var dataTransferObfuscation: DataTransferObfuscation?

        var defaultSequence: String?

        struct Association: Sendable {
            var window: String
            var keystrokeSequence: String
        }

        var association: [Association]?
    }
}
