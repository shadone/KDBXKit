//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct Root: Sendable {
        let group: Group

        /// When the user deletes an object (group, entry, ...), an item is created in this list. When synchronizing/merging database files, this information can be used to decide whether an object has been deleted.
        let deletedObjects: [DeletedObject]?
    }
}
