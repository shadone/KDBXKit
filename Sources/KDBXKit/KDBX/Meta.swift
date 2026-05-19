//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// Vault-level settings — name, description, recycle-bin pointer,
    /// custom icons, default username, master-key-rotation policy,
    /// history limits, memory-protection defaults, and the
    /// per-setting modification timestamps that sync / merge tooling
    /// uses to pick the freshest side.
    ///
    /// Lives at ``KDBX/meta``. Most fields are user-visible
    /// preferences a host app exposes through a "vault settings"
    /// dialog; a few (the various `*Changed` timestamps,
    /// ``settingsChanged``, ``headerHash``) are bookkeeping that
    /// KDBXKit keeps consistent automatically.
    ///
    /// **Invariant:** mutating any user-visible field bumps
    /// `settingsChanged` (the umbrella "settings touched at" timestamp
    /// KDBX clients read to pick the fresher side of a sync) via the
    /// field's `didSet`. `headerHash` and `settingsChanged` itself are
    /// exempt — `headerHash` is a legacy KDBX-3 integrity field, and
    /// the umbrella timestamp doesn't observe itself. `generator` IS
    /// tracked: a same-value re-stamp during a save is a no-op (see
    /// the idempotent-write guard below), but a cross-client save
    /// that actually changes the writer name records a real settings
    /// change.
    ///
    /// **Idempotent writes are no-ops.** Each `didSet` guards on
    /// `oldValue != current` so writing the existing value back
    /// (round-trip deserialisation, defensive re-application, syncing
    /// the same payload twice) doesn't spuriously advance the change
    /// timestamps. Without this guard, repaint-style code that
    /// re-assigns a field with its current value would falsely
    /// register as an edit and lose against a real edit on the other
    /// side of a sync.
    ///
    /// Deserialization is the one exception: `didSet` doesn't fire
    /// during the initializer's initial property assignments, so
    /// callers that need to reconstruct a `Meta` straight from disk
    /// build the full argument list and pass it to `init(...)` in
    /// one shot. The XML reader uses this pattern — see
    /// `XMLDocumentReader.parseMeta`.
    struct Meta: Sendable, Equatable {
        /// Name of the application that has generated the XML document.
        /// Bumps `settingsChanged` only when the value actually changes
        /// — a same-value re-stamp (the writer re-asserts "Passie" on
        /// every save) is a no-op thanks to the `oldValue` guard, so
        /// the umbrella timestamp still means "something a user cares
        /// about changed". A cross-client save (e.g. KeePassXC opens a
        /// Passie vault and saves it back) IS a real settings change
        /// and is recorded.
        public var generator: String? {
            didSet {
                guard generator != oldValue else { return }
                settingsChanged = Date()
            }
        }

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

        /// User-visible vault name (the string a host app shows in
        /// the title bar / file list). Mutating it auto-bumps
        /// ``databaseNameChanged`` and ``settingsChanged``.
        public var databaseName: String? {
            didSet {
                guard databaseName != oldValue else { return }
                let now = Date()
                databaseNameChanged = now
                settingsChanged = now
            }
        }

        /// When ``databaseName`` was last edited. Bumped by the
        /// observer on `databaseName`; sync / merge tooling reads
        /// this to pick the freshest name on conflict.
        public var databaseNameChanged: Date? {
            didSet {
                guard databaseNameChanged != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Free-form vault description shown alongside the name in
        /// vault chooser / settings UIs. Optional. Mutating bumps
        /// ``databaseDescriptionChanged`` and ``settingsChanged``.
        public var databaseDescription: String? {
            didSet {
                guard databaseDescription != oldValue else { return }
                let now = Date()
                databaseDescriptionChanged = now
                settingsChanged = now
            }
        }

        /// When ``databaseDescription`` was last edited. Bumped by
        /// the observer on `databaseDescription`.
        public var databaseDescriptionChanged: Date? {
            didSet {
                guard databaseDescriptionChanged != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// User name that is used by default for new entries.
        public var defaultUserName: String? {
            didSet {
                guard defaultUserName != oldValue else { return }
                let now = Date()
                defaultUserNameChanged = now
                settingsChanged = now
            }
        }

        /// When ``defaultUserName`` was last edited.
        public var defaultUserNameChanged: Date? {
            didSet {
                guard defaultUserNameChanged != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// UUID of the group that is used as recycle bin. Zero UUID = create
        /// new group when necessary.
        public var recycleBinUUID: UUID? {
            didSet {
                guard recycleBinUUID != oldValue else { return }
                let now = Date()
                recycleBinChanged = now
                settingsChanged = now
            }
        }

        /// When the recycle-bin pointer or enabled flag was last
        /// edited. Bumped by observers on ``recycleBinUUID`` and
        /// ``recycleBinEnabled``.
        public var recycleBinChanged: Date? {
            didSet {
                guard recycleBinChanged != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// UUID of a group whose entries the UI offers as templates
        /// when creating new entries (a "starter set" of common
        /// shapes — bank login, credit card, secure note). Nil
        /// disables the templates feature for the vault.
        public var entryTemplatesGroup: UUID? {
            didSet {
                guard entryTemplatesGroup != oldValue else { return }
                let now = Date()
                entryTemplatesGroupChanged = now
                settingsChanged = now
            }
        }

        /// When ``entryTemplatesGroup`` was last edited.
        public var entryTemplatesGroupChanged: Date? {
            didSet {
                guard entryTemplatesGroupChanged != oldValue else { return }
                settingsChanged = Date()
            }
        }

        // MARK: - Tracked field — master key change date

        //
        // No paired value field — only the timestamp itself is part of
        // Meta. The key material lives in the file header / KDF
        // parameters, not Meta. Mutating this bumps `settingsChanged`
        // like any other Meta field.

        /// Last date/time when the master key has been changed.
        public var masterKeyChanged: Date? {
            didSet {
                guard masterKeyChanged != oldValue else { return }
                settingsChanged = Date()
            }
        }

        // MARK: - Tracked scalars (bump `settingsChanged` only)

        /// Number of days until history entries are deleted in a database
        /// maintenance operation.
        public var maintenanceHistoryDays: UInt32? {
            didSet {
                guard maintenanceHistoryDays != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Database color. The user interface can colorize elements with
        /// this color to help the user identify the database.
        public var color: Color? {
            didSet {
                guard color != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Number of days until a change of the master key is recommended.
        /// `.never` opts out.
        public var masterKeyChangeRec: ValueOrNever<UInt64>? {
            didSet {
                guard masterKeyChangeRec != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Number of days until a change of the master key is enforced.
        /// `.never` opts out.
        public var masterKeyChangeForce: ValueOrNever<UInt64>? {
            didSet {
                guard masterKeyChangeForce != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// If true, a change of the master key should be enforced once
        /// directly after the user opens the database.
        public var masterKeyChangeForceOnce: Bool? {
            didSet {
                guard masterKeyChangeForceOnce != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Per-standard-field protection defaults the UI applies to
        /// new entries — whether `Title` / `UserName` / `Password` /
        /// `URL` / `Notes` are marked `Protected="True"` on creation.
        /// See ``MemoryProtectionConfig`` for the field-by-field
        /// details (and the spec's caveat that KeePass may reset
        /// these on open).
        public var memoryProtection: MemoryProtectionConfig? {
            didSet {
                guard memoryProtection != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Vault-embedded images that entries and groups can use as
        /// custom icons via ``Entry/customIconUUID`` /
        /// ``Group/customIconUUID``. See ``CustomIcon``.
        public var customIcons: [CustomIcon] {
            didSet {
                guard customIcons != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Whether the recycle-bin workflow is enabled. When `false`,
        /// deleting an entry or group removes it outright (a
        /// tombstone is added to ``Root/deletedObjects``); when
        /// `true`, the item is moved to ``recycleBinUUID`` instead.
        /// `nil` defers to the client's default (`true` in KeePass).
        ///
        /// > Note: Only bumps ``settingsChanged``, not
        /// > ``recycleBinChanged`` — the spec ties the latter to the
        /// > recycle-bin *pointer* (``recycleBinUUID``), not the
        /// > enable flag.
        public var recycleBinEnabled: Bool? {
            didSet {
                guard recycleBinEnabled != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Maximum number of history entries that each entry may have.
        /// `.unlimited` opts out.
        public var historyMaxItems: ValueOrUnlimited<UInt32>? {
            didSet {
                guard historyMaxItems != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// Maximum estimated size in bytes (in the process memory) of the
        /// history of each entry. `.unlimited` opts out.
        public var historyMaxSize: ValueOrUnlimited<UInt64>? {
            didSet {
                guard historyMaxSize != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// UI hint: UUID of whichever group was selected when the
        /// vault was last viewed. Lets clients restore the user's
        /// place on next open. Not security-relevant.
        public var lastSelectedGroup: UUID? {
            didSet {
                guard lastSelectedGroup != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// UI hint: UUID of whichever group was scrolled to the top
        /// of the tree view when the vault was last viewed. Not
        /// security-relevant.
        public var lastTopVisibleGroup: UUID? {
            didSet {
                guard lastTopVisibleGroup != oldValue else { return }
                settingsChanged = Date()
            }
        }

        /// In this element, the content of each binary is stored. Used only
        /// in unencrypted XML files and in KDBX files prior to version 4. In
        /// KDBX ≥ 4, binaries are stored in the inner header (encrypted)
        /// instead.
        // public var binaries: [TProtectedBinaryDef]?

        /// Vault-level custom key/value items with per-item
        /// modification timestamps. Use this for plugin / host-app
        /// metadata that applies to the whole vault (sync-server
        /// pointer, last-export marker, etc.). Per-entry and
        /// per-group custom data uses the plainer
        /// ``CustomDataItem``.
        public var customData: [CustomDataWithTimes] {
            didSet {
                guard customData != oldValue else { return }
                settingsChanged = Date()
            }
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
