//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A vault-level custom-data entry — string key/value pair plus a
    /// modification timestamp.
    ///
    /// Used by ``Meta/customData`` (where the timestamp lets sync /
    /// merge tooling decide which side's value is newer). Entries and
    /// groups use the plainer ``CustomDataItem`` without a timestamp.
    /// Same namespacing recommendation: prefix keys to avoid
    /// collisions (e.g. `AppName_FieldName`).
    struct CustomDataWithTimes: Sendable, Equatable {
        /// Item key. Should be unique within ``Meta/customData``;
        /// prefix with an app or plugin name to avoid collisions
        /// with other tools that touch the vault.
        public var key: String

        /// Item value. Plain `String` — no protected-in-memory
        /// treatment. Don't put secrets here.
        public var value: String

        /// When this item was last edited. Host apps update this on
        /// any change to ``value``; sync / merge tooling consults it
        /// to pick the most recent side.
        public var lastModificationTime: Date?

        public init(key: String, value: String, lastModificationTime: Date? = nil) {
            self.key = key
            self.value = value
            self.lastModificationTime = lastModificationTime
        }
    }
}
