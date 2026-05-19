//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// The top-level wrapper around a vault's group hierarchy.
    ///
    /// Every KDBX file has exactly one `Root`. It carries the
    /// outermost ``Group`` (under which all user-visible folders nest)
    /// plus the tombstone list (``deletedObjects``) used by sync /
    /// merge algorithms to distinguish "never existed" from
    /// "explicitly deleted".
    struct Root: Sendable, Equatable {
        /// The top-level group of the vault. All user-visible folders
        /// and entries live in this group's `groups` / `entries`
        /// arrays (or deeper).
        public var group: Group

        /// Tombstones for deleted items. When the user deletes a group
        /// or entry, an entry is added here with the deleted item's
        /// UUID and deletion timestamp. Sync / merge tooling consults
        /// this list to decide whether an object that's missing from
        /// one side was deleted (and should stay deleted) versus
        /// simply never created (and should be propagated). KDBXKit
        /// preserves the list across reads and writes; it does not
        /// generate tombstones automatically — host apps that perform
        /// deletions should record them here.
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
