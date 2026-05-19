//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A tombstone recording that an entry or group was deleted.
    ///
    /// Stored in ``Root/deletedObjects``. Sync / merge tooling reads
    /// these to distinguish "the item never existed on this side"
    /// from "the item was explicitly deleted on this side" — a
    /// crucial difference when merging two versions of a vault.
    ///
    /// KDBXKit preserves tombstones across reads and writes but does
    /// not generate them automatically; host apps that perform
    /// deletions should append a `DeletedObject` to
    /// ``Root/deletedObjects`` with the deleted item's `uuid` and
    /// the current time.
    struct DeletedObject: Sendable, Equatable {
        /// UUID of the deleted entry or group.
        public let uuid: UUID

        /// When the item was deleted. Used by sync / merge tooling to
        /// decide if a deletion is newer than the surviving copy on
        /// the other side.
        public let deletionTime: Date

        public init(uuid: UUID, deletionTime: Date) {
            self.uuid = uuid
            self.deletionTime = deletionTime
        }
    }
}
