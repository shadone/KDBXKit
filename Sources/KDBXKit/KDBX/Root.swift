//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct Root: Sendable, Equatable {
        public var group: Group

        /// When the user deletes an object (group, entry, ...), an item is created in this list. When synchronizing/merging database files, this information can be used to decide whether an object has been deleted.
        public var deletedObjects: [DeletedObject]

        public init(
            group: Group,
            deletedObjects: [DeletedObject]
        ) {
            self.group = group
            self.deletedObjects = deletedObjects
        }
    }
}
