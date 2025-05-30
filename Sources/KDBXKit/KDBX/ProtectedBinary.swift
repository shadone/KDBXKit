//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct ProtectedBinary: Sendable, Equatable {
        public enum Value: Sendable, Equatable {
            /// Inline binary data
            case inline(Data)
            /// Reference to a binary content stored in the inner header (KDBX file) or in the Meta/Binaries element (unencrypted XML file).
            case ref(UInt32)
        }

        public let key: String
        public let value: Value
    }
}
