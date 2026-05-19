//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A vault-embedded image that entries and groups can use as a
    /// custom icon — instead of (or in addition to) the
    /// ``Entry/iconID`` / ``Group/iconID`` standard-set integers.
    ///
    /// Custom icons live in ``Meta/customIcons``. An ``Entry`` or
    /// ``Group`` references one by setting
    /// ``Entry/customIconUUID`` / ``Group/customIconUUID`` to the
    /// icon's ``uuid``; when non-nil that reference shadows the
    /// standard icon ID. KDBX 4.1 added the ``name`` and
    /// ``lastModificationTime`` fields for sync-friendly bookkeeping;
    /// 4.0 and 3.1 don't carry them and decode to `nil`.
    struct CustomIcon: Sendable, Equatable {
        /// Stable identity for the custom icon. Entries / groups
        /// point at this UUID via `customIconUUID`.
        public let uuid: UUID

        /// Image bytes. Format isn't constrained by the KDBX spec
        /// beyond "something common UI clients can display" — in
        /// practice PNG is universal; JPEG and ICO also work.
        public let data: Data

        /// Human-readable name for the icon. Optional; KDBX 4.0 and
        /// earlier omit this field entirely.
        public let name: String?

        /// When the icon was last edited (file bytes or name). Used
        /// by sync / merge tooling to pick the most recent side.
        /// Optional in the same KDBX-version sense as ``name``.
        public let lastModificationTime: Date?

        public init(uuid: UUID, data: Data, name: String?, lastModificationTime: Date?) {
            self.uuid = uuid
            self.data = data
            self.name = name
            self.lastModificationTime = lastModificationTime
        }
    }
}
