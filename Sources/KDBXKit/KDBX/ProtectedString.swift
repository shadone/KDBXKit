//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct ProtectedString: Sendable, Equatable {
        public enum Value: Sendable, Equatable {
            /// Plaintext string.
            case regular(String)

            /// The decrypted value of the protected string.
            ///
            /// In the XML document the Protect String value is stored as a binary data encrypted using Inner Encryption.
            /// While parsing the XML we decrypt the values and this is the result.
            case unprotected(String)

            /// - note: This type is only used in an unencrypted XML file.
            case protectedInMemory(String)

            /// Returns the raw string of the ``ProtectedString`` value.
            public var stringValue: String {
                switch self {
                case .regular(let string):
                    return string
                case .unprotected(let string):
                    return string
                case .protectedInMemory(let string):
                    return string
                }
            }
        }

        public var key: String
        public var value: Value

        public init(key: String, value: Value) {
            self.key = key
            self.value = value
        }
    }
}
