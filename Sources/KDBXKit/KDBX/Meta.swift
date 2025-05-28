//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    public struct Meta: Sendable {
        /// Name of the application that has generated the XML document.
        public var generator: String?

        /// Hash of the (unencrypted) header of a KDBX file. Used only in KDBX files prior to version 4. In KDBX ≥ 4, the integrity and the authenticity are ensured using a HMAC instead (see KDBX spec.).
        public var headerHash: String?

        /// Last date/time when a database setting (stored in the Meta element) has been changed.
        public var settingsChanged: Date?

        /// The name of the database.
        public var databaseName: String?

        public var databaseNameChanged: Date?

        public var databaseDescription: String?

        public var databaseDescriptionChanged: Date?

        /// User name that is used by default for new entries.
        public var defaultUserName: String?

        public var defaultUserNameChanged: Date?

        /// Number of days until history entries are deleted in a database maintenance operation.
        public var maintenanceHistoryDays: UInt32?

        /// Database color. The user interface can colorize elements with this color in order to allow the user to quickly identify the database.
        public var color: Color?

        /// Last date/time when the master key has been changed.
        public var masterKeyChanged: Date?

        /// Number of days until a change of the master key is recommended. -1 means never.
        public var masterKeyChangeRec: ValueOrNever<UInt64>?

        /// Number of days until a change of the master key is enforced. -1 means never.
        public var masterKeyChangeForce: ValueOrNever<UInt64>?

        /// If true, a change of the master key should be enforced once directly after the user opens the database.
        public var masterKeyChangeForceOnce: Bool?

        public var memoryProtection: MemoryProtectionConfig?

        public var customIcons: [CustomIcon]?

        public var recycleBinEnabled: Bool?

        /// UUID of the group that is used as recycle bin. Zero UUID = create new group when necessary.
        public var recycleBinUUID: UUID?

        public var recycleBinChanged: Date?

        public var entryTemplatesGroup: UUID?

        public var entryTemplatesGroupChanged: Date?

        /// Maximum number of history entries that each entry may have. -1 means unlimited.
        public var historyMaxItems: ValueOrUnlimited<UInt32>?

        /// Maximum estimated size in bytes (in the process memory) of the history of each entry. -1 means unlimited.
        public var historyMaxSize: ValueOrUnlimited<UInt64>?

        public var lastSelectedGroup: UUID?

        public var lastTopVisibleGroup: UUID?

        /// In this element, the content of each binary is stored. Used only in unencrypted XML files and in KDBX files prior to version 4. In KDBX ≥ 4, binaries are stored in the inner header (encrypted) instead.
        // public var binaries: [TProtectedBinaryDef]?

        public var customData: [CustomDataWithTimes]?
    }
}
