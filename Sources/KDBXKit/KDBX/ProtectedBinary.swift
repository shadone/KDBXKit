//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    public struct ProtectedBinary: Sendable {
        public let key: String

        // public let value: ??? TODO: I dont understand the schema

        /// Reference to a binary content stored in the inner header (KDBX file) or in the Meta/Binaries element (unencrypted XML file).
        public let ref: UInt32
    }
}
