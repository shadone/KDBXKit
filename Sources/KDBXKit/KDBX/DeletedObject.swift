//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct DeletedObject: Sendable {
        let uuid: UUID
        let deletionTime: Date
    }
}
