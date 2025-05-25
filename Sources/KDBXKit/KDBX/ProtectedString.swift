//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    enum ProtectedString: Sendable {
        /// Used in a KDBX file.
        case protected(Data)

        /// Used in an unencrypted XML file.
        case protectedInMemory(Data)
    }
}
