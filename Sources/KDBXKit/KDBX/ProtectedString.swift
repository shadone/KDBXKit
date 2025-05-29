//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    public struct ProtectedString: Sendable, Equatable {
        public enum Value: Sendable, Equatable {
            /// Plaintext string.
            case regular(String)

            /// Protected value, encrypted using Inner Encryption.
            ///
            /// - note: This type is used in KDBX file.
            case protected(Data)

            /// The protected value that was decrypted
            case unprotected(String)

            /// - note: This type is only used in an unencrypted XML file.
            case protectedInMemory(String)
        }

        public var key: String
        public var value: Value
    }
}
