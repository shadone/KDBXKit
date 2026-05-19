//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// Timestamps and the expiry / location-changed audit trail for an
    /// entry or group.
    ///
    /// Most fields are optional because legacy 3.x clients sometimes
    /// omit them. The writer leaves the on-disk values untouched on
    /// round-trip; only the host app or the KeePass UI normally
    /// updates them (`lastModificationTime` on edit,
    /// `lastAccessTime` on read, `usageCount` on auto-type, etc.).
    struct Times: Sendable, Equatable {
        /// When the entry/group was originally created.
        public var creationTime: Date?

        /// When the entry/group was last edited. Host apps should
        /// update this on any change to the item's fields.
        public var lastModificationTime: Date?

        /// When the entry/group was last opened or read. In practice,
        /// reads aren't reliably recorded — KeePass treats access
        /// time as "not a database change", so most clients only
        /// update it under specific UI conditions (see the
        /// `UIFlags 0x20000` discussion at
        /// <https://keepass.info/help/v2_dev/customize.html#uiflags>).
        /// Treat as a soft hint, not a security audit log.
        public var lastAccessTime: Date?

        /// When the entry/group should be considered expired.
        /// Meaningful only when ``expires`` is `true`. Hosts surface
        /// this as a "password is X days overdue for rotation" cue.
        public var expiryTime: Date?

        /// Whether ``expiryTime`` is active. `false` (or `nil`) means
        /// "never expires"; `true` means "consult ``expiryTime``".
        public var expires: Bool?

        /// How many times the entry has been "used" — typically
        /// incremented on auto-type or password reveal. Same
        /// reliability caveat as ``lastAccessTime``: clients update
        /// it inconsistently.
        public var usageCount: UInt64?

        /// When the entry/group was last moved to a different parent.
        /// Used by sync / merge tools to figure out the
        /// most-recently-authoritative location for the item.
        public var locationChanged: Date?

        public init(
            creationTime: Date? = nil,
            lastModificationTime: Date? = nil,
            lastAccessTime: Date? = nil,
            expiryTime: Date? = nil,
            expires: Bool? = nil,
            usageCount: UInt64? = nil,
            locationChanged: Date? = nil
        ) {
            self.creationTime = creationTime
            self.lastModificationTime = lastModificationTime
            self.lastAccessTime = lastAccessTime
            self.expiryTime = expiryTime
            self.expires = expires
            self.usageCount = usageCount
            self.locationChanged = locationChanged
        }
    }
}
