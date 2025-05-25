//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct Meta: Sendable {
        /// Name of the application that has generated the XML document.
        let generator: String?

        /// Hash of the (unencrypted) header of a KDBX file. Used only in KDBX files prior to version 4. In KDBX ≥ 4, the integrity and the authenticity are ensured using a HMAC instead (see KDBX spec.).
        let headerHash: String?

        /// Last date/time when a database setting (stored in the Meta element) has been changed.
        let settingsChanged: Date?

        /// The name of the database.
        let databaseName: String?

        let databaseNameChanged: Date?

        let databaseDescription: String?

        let databaseDescriptionChanged: Date?

        /// User name that is used by default for new entries.
        let defaultUserName: String?

        let defaultUserNameChanged: Date?

        /// Number of days until history entries are deleted in a database maintenance operation.
        let maintenanceHistoryDays: UInt32?

        /// Database color. The user interface can colorize elements with this color in order to allow the user to quickly identify the database.
        let color: Color?

        /// Last date/time when the master key has been changed.
        let masterKeyChanged: Date?

        /// Number of days until a change of the master key is recommended. -1 means never.
        let masterKeyChangeRec: ValueOrNever<UInt64>?

        /// Number of days until a change of the master key is enforced. -1 means never.
        let masterKeyChangeForce: ValueOrNever<UInt64>?

        /// If true, a change of the master key should be enforced once directly after the user opens the database.
        let MasterKeyChangeForceOnce: Bool?

        let memoryProtection: MemoryProtectionConfig?

        let customIcons: [CustomIcon]?

        let recycleBinEnabled: Bool?

        /// UUID of the group that is used as recycle bin. Zero UUID = create new group when necessary.
        let recycleBinUUID: UUID?

        let recycleBinChanged: Date?

        let entryTemplatesGroup: UUID?

        let entryTemplatesGroupChanged: Date?

        /// Maximum number of history entries that each entry may have. -1 means unlimited.
        let historyMaxItems: ValueOrUnlimited<UInt32>?

        /// Maximum estimated size in bytes (in the process memory) of the history of each entry. -1 means unlimited.
        let historyMaxSize: ValueOrUnlimited<UInt64>?

        let lastSelectedGroup: UUID?

        let lastTopVisibleGroup: UUID?

        /// In this element, the content of each binary is stored. Used only in unencrypted XML files and in KDBX files prior to version 4. In KDBX ≥ 4, binaries are stored in the inner header (encrypted) instead.
        //let binaries: [TProtectedBinaryDef]?

        let customData: [CustomDataWithTimes]?
    }
}
