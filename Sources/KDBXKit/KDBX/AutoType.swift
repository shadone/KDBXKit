//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    /// https://keepass.info/help/base/autotype.html
    public struct AutoType: Sendable, Equatable {
        public var enabled: Bool?

        public enum DataTransferObfuscation: Int32, Sendable, Equatable {
            /// No obfuscation.
            case noObfuscation = 0

            /// Two-channel auto-type obfuscation. https://keepass.info/help/v2/autotype_obfuscation.html
            case twoChannelObfuscation = 1
        }

        public var dataTransferObfuscation: DataTransferObfuscation?

        public var defaultSequence: String?

        public struct Association: Sendable, Equatable {
            public var window: String
            public var keystrokeSequence: String
        }

        public var association: [Association]?
    }
}
