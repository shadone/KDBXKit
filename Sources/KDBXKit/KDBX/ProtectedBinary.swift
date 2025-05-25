//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct ProtectedBinary: Sendable {
        let key: String

        //let value: ??? TODO: I dont understand the schema

        /// Reference to a binary content stored in the inner header (KDBX file) or in the Meta/Binaries element (unencrypted XML file).
        let ref: UInt32
    }
}
