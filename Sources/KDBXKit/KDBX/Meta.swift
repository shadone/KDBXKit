//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// Database-wide settings stored in the KDBX `<Meta>` element.
    ///
    /// **Invariant:** mutating any user-visible field bumps
    /// `settingsChanged` (the umbrella "settings touched at" timestamp
    /// KDBX clients read to pick the fresher side of a sync) via the
    /// field's `didSet`. `generator`, `headerHash`, and
    /// `settingsChanged` itself are exempt — `generator` is writer-
    /// stamped on every save (bumping every time would make
    /// `settingsChanged` meaningless), `headerHash` is a legacy
    /// KDBX-3 integrity field, and the umbrella timestamp doesn't
    /// observe itself.
    ///
    /// Deserialization is the one exception: `didSet` doesn't fire
    /// during the initializer's initial property assignments, so
    /// callers that need to reconstruct a `Meta` straight from disk
    /// build the full argument list and pass it to `init(...)` in
    /// one shot. The XML reader uses this pattern — see
    /// `XMLDocumentReader.parseMeta`.
    struct Meta: Sendable, Equatable {
        /// Name of the application that has generated the XML document.
        /// **Not** tracked by `settingsChanged` — the writer stamps this
        /// on every save, so bumping would make the umbrella timestamp
        /// meaningless.
        public var generator: String?

        /// Hash of the (unencrypted) header of a KDBX file. Used only in KDBX
        /// files prior to version 4. In KDBX ≥ 4, integrity and authenticity
        /// are ensured via HMAC instead. **Not** tracked by `settingsChanged`
        /// — this is an internal integrity artifact, not a user setting.
        public var headerHash: String?

        /// Last date/time when any database setting (stored in the Meta
        /// element) changed. Bumped automatically by every other field's
        /// `didSet`; callers don't normally write this directly.
        public var settingsChanged: Date?

        // MARK: - Tracked fields with paired `*Changed` companions
        //
        // Pairs like (databaseName, databaseNameChanged) carry both the
        // value and a per-field modification timestamp. Mutating the
        // value field bumps both the companion and `settingsChanged`;
        // mutating the companion directly bumps `settingsChanged`. This
        // mirrors what KDBX clients expect on the wire — `DatabaseName`
        // and `DatabaseNameChanged` always advance together when the
        // name is edited.

        /// The name of the database.
        public var databaseName: String? {
            didSet {
                let now = Date()
                databaseNameChanged = now
                settingsChanged = now
            }
        }

        public var databaseNameChanged: Date? {
            didSet { settingsChanged = Date() }
        }

        public var databaseDescription: String? {
            didSet {
                let now = Date()
                databaseDescriptionChanged = now
                settingsChanged = now
            }
        }

        public var databaseDescriptionChanged: Date? {
            didSet { settingsChanged = Date() }
        }

        /// User name that is used by default for new entries.
        public var defaultUserName: String? {
            didSet {
                let now = Date()
                defaultUserNameChanged = now
                settingsChanged = now
            }
        }

        public var defaultUserNameChanged: Date? {
            didSet { settingsChanged = Date() }
        }

        /// UUID of the group that is used as recycle bin. Zero UUID = create
        /// new group when necessary.
        public var recycleBinUUID: UUID? {
            didSet {
                let now = Date()
                recycleBinChanged = now
                settingsChanged = now
            }
        }

        public var recycleBinChanged: Date? {
            didSet { settingsChanged = Date() }
        }

        public var entryTemplatesGroup: UUID? {
            didSet {
                let now = Date()
                entryTemplatesGroupChanged = now
                settingsChanged = now
            }
        }

        public var entryTemplatesGroupChanged: Date? {
            didSet { settingsChanged = Date() }
        }

        // MARK: - Tracked field — master key change date
        //
        // No paired value field — only the timestamp itself is part of
        // Meta. The key material lives in the file header / KDF
        // parameters, not Meta. Mutating this bumps `settingsChanged`
        // like any other Meta field.

        /// Last date/time when the master key has been changed.
        public var masterKeyChanged: Date? {
            didSet { settingsChanged = Date() }
        }

        // MARK: - Tracked scalars (bump `settingsChanged` only)

        /// Number of days until history entries are deleted in a database
        /// maintenance operation.
        public var maintenanceHistoryDays: UInt32? {
            didSet { settingsChanged = Date() }
        }

        /// Database color. The user interface can colorize elements with
        /// this color to help the user identify the database.
        public var color: Color? {
            didSet { settingsChanged = Date() }
        }

        /// Number of days until a change of the master key is recommended.
        /// `.never` opts out.
        public var masterKeyChangeRec: ValueOrNever<UInt64>? {
            didSet { settingsChanged = Date() }
        }

        /// Number of days until a change of the master key is enforced.
        /// `.never` opts out.
        public var masterKeyChangeForce: ValueOrNever<UInt64>? {
            didSet { settingsChanged = Date() }
        }

        /// If true, a change of the master key should be enforced once
        /// directly after the user opens the database.
        public var masterKeyChangeForceOnce: Bool? {
            didSet { settingsChanged = Date() }
        }

        public var memoryProtection: MemoryProtectionConfig? {
            didSet { settingsChanged = Date() }
        }

        public var customIcons: [CustomIcon] {
            didSet { settingsChanged = Date() }
        }

        public var recycleBinEnabled: Bool? {
            didSet { settingsChanged = Date() }
        }

        /// Maximum number of history entries that each entry may have.
        /// `.unlimited` opts out.
        public var historyMaxItems: ValueOrUnlimited<UInt32>? {
            didSet { settingsChanged = Date() }
        }

        /// Maximum estimated size in bytes (in the process memory) of the
        /// history of each entry. `.unlimited` opts out.
        public var historyMaxSize: ValueOrUnlimited<UInt64>? {
            didSet { settingsChanged = Date() }
        }

        public var lastSelectedGroup: UUID? {
            didSet { settingsChanged = Date() }
        }

        public var lastTopVisibleGroup: UUID? {
            didSet { settingsChanged = Date() }
        }

        /// In this element, the content of each binary is stored. Used only
        /// in unencrypted XML files and in KDBX files prior to version 4. In
        /// KDBX ≥ 4, binaries are stored in the inner header (encrypted)
        /// instead.
        // public var binaries: [TProtectedBinaryDef]?

        public var customData: [CustomDataWithTimes] {
            didSet { settingsChanged = Date() }
        }

        /// Memberwise initializer. `didSet` observers do **not** fire during
        /// these initial assignments — Swift treats them as the property's
        /// first write. Deserializers (XML reader, lazy/eager open paths)
        /// rely on this: they accumulate parsed values into locals and
        /// hand the full list off in one shot, preserving on-disk
        /// timestamps verbatim. Code that wants the bumping behavior
        /// should build a Meta with the constructor and then mutate
        /// fields afterwards.
        public init(
            generator: String? = nil,
            headerHash: String? = nil,
            settingsChanged: Date? = nil,
            databaseName: String? = nil,
            databaseNameChanged: Date? = nil,
            databaseDescription: String? = nil,
            databaseDescriptionChanged: Date? = nil,
            defaultUserName: String? = nil,
            defaultUserNameChanged: Date? = nil,
            maintenanceHistoryDays: UInt32? = nil,
            color: Color? = nil,
            masterKeyChanged: Date? = nil,
            masterKeyChangeRec: ValueOrNever<UInt64>? = nil,
            masterKeyChangeForce: ValueOrNever<UInt64>? = nil,
            masterKeyChangeForceOnce: Bool? = nil,
            memoryProtection: MemoryProtectionConfig? = nil,
            customIcons: [CustomIcon] = [],
            recycleBinEnabled: Bool? = nil,
            recycleBinUUID: UUID? = nil,
            recycleBinChanged: Date? = nil,
            entryTemplatesGroup: UUID? = nil,
            entryTemplatesGroupChanged: Date? = nil,
            historyMaxItems: ValueOrUnlimited<UInt32>? = nil,
            historyMaxSize: ValueOrUnlimited<UInt64>? = nil,
            lastSelectedGroup: UUID? = nil,
            lastTopVisibleGroup: UUID? = nil,
            customData: [CustomDataWithTimes] = []
        ) {
            self.generator = generator
            self.headerHash = headerHash
            self.settingsChanged = settingsChanged
            self.databaseName = databaseName
            self.databaseNameChanged = databaseNameChanged
            self.databaseDescription = databaseDescription
            self.databaseDescriptionChanged = databaseDescriptionChanged
            self.defaultUserName = defaultUserName
            self.defaultUserNameChanged = defaultUserNameChanged
            self.maintenanceHistoryDays = maintenanceHistoryDays
            self.color = color
            self.masterKeyChanged = masterKeyChanged
            self.masterKeyChangeRec = masterKeyChangeRec
            self.masterKeyChangeForce = masterKeyChangeForce
            self.masterKeyChangeForceOnce = masterKeyChangeForceOnce
            self.memoryProtection = memoryProtection
            self.customIcons = customIcons
            self.recycleBinEnabled = recycleBinEnabled
            self.recycleBinUUID = recycleBinUUID
            self.recycleBinChanged = recycleBinChanged
            self.entryTemplatesGroup = entryTemplatesGroup
            self.entryTemplatesGroupChanged = entryTemplatesGroupChanged
            self.historyMaxItems = historyMaxItems
            self.historyMaxSize = historyMaxSize
            self.lastSelectedGroup = lastSelectedGroup
            self.lastTopVisibleGroup = lastTopVisibleGroup
            self.customData = customData
        }
    }
}
