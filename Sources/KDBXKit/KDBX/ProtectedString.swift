//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    public struct ProtectedString: Sendable {
        public enum Value: Sendable {
            /// Plaintext string.
            case regular(String)

            /// Used in a KDBX file.
            case protected(Data)

            /// Used in an unencrypted XML file.
            case protectedInMemory(String)
        }

        public let key: String
        public let value: Value
    }
}
