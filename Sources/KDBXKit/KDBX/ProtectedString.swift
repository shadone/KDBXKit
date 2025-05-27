//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct ProtectedString {
        enum Value: Sendable {
            /// Plaintext string.
            case regular(String)

            /// Used in a KDBX file.
            case protected(Data)

            /// Used in an unencrypted XML file.
            case protectedInMemory(String)
        }

        let key: String
        let value: Value
    }
}
