//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct Meta: Sendable {
        /// Name of the application that has generated the XML document.
        var generator: String?

        /// Hash of the (unencrypted) header of a KDBX file. Used only in KDBX files prior to version 4. In KDBX ≥ 4, the integrity and the authenticity are ensured using a HMAC instead (see KDBX spec.).
        var headerHash: String?

        /// Last date/time when a database setting (stored in the Meta element) has been changed.
        var settingsChanged: Date?

        /// The name of the database.
        var databaseName: String?

        var databaseNameChanged: Date?

        var databaseDescription: String?

        var databaseDescriptionChanged: Date?

        /// User name that is used by default for new entries.
        var defaultUserName: String?

        var defaultUserNameChanged: Date?

        /// Number of days until history entries are deleted in a database maintenance operation.
        var maintenanceHistoryDays: UInt32?

        /// Database color. The user interface can colorize elements with this color in order to allow the user to quickly identify the database.
        var color: Color?

        /// Last date/time when the master key has been changed.
        var masterKeyChanged: Date?

        /// Number of days until a change of the master key is recommended. -1 means never.
        var masterKeyChangeRec: ValueOrNever<UInt64>?

        /// Number of days until a change of the master key is enforced. -1 means never.
        var masterKeyChangeForce: ValueOrNever<UInt64>?

        /// If true, a change of the master key should be enforced once directly after the user opens the database.
        var masterKeyChangeForceOnce: Bool?

        var memoryProtection: MemoryProtectionConfig?

        var customIcons: [CustomIcon]?

        var recycleBinEnabled: Bool?

        /// UUID of the group that is used as recycle bin. Zero UUID = create new group when necessary.
        var recycleBinUUID: UUID?

        var recycleBinChanged: Date?

        var entryTemplatesGroup: UUID?

        var entryTemplatesGroupChanged: Date?

        /// Maximum number of history entries that each entry may have. -1 means unlimited.
        var historyMaxItems: ValueOrUnlimited<UInt32>?

        /// Maximum estimated size in bytes (in the process memory) of the history of each entry. -1 means unlimited.
        var historyMaxSize: ValueOrUnlimited<UInt64>?

        var lastSelectedGroup: UUID?

        var lastTopVisibleGroup: UUID?

        /// In this element, the content of each binary is stored. Used only in unencrypted XML files and in KDBX files prior to version 4. In KDBX ≥ 4, binaries are stored in the inner header (encrypted) instead.
        // var binaries: [TProtectedBinaryDef]?

        var customData: [CustomDataWithTimes]?
    }
}
