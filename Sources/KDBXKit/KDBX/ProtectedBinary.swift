//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct ProtectedBinary: Sendable, Equatable {
        public enum Value: Sendable, Equatable {
            /// Inline binary data. The `protected` flag mirrors the
            /// `Protected="True"` attribute on the `<Value>` element
            /// in the entry XML — present in KDBX 3.1 binaries and in
            /// any KDBX 4 entry that chose inline storage rather than
            /// a pool reference.
            case inline(Data, protected: Bool)
            /// Reference to a binary content stored in the inner header (KDBX file) or in the Meta/Binaries element (unencrypted XML file).
            /// The protected status for a ref lives on the pool entry's
            /// `shouldBeProtected` flag, not here — refs are pointers,
            /// not data.
            case ref(UInt32)
        }

        public let key: String
        public let value: Value

        public init(key: String, value: Value) {
            self.key = key
            self.value = value
        }
    }
}
