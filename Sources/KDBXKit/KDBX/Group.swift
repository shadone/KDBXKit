//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A folder in the vault's group tree.
    ///
    /// Holds child entries (``entries``) and nested subgroups (``groups``),
    /// plus per-folder display preferences (name, icon, colors), search /
    /// auto-type policy that descendants inherit, and recycle-bin
    /// restoration metadata. The root of every KDBX file is a `Group`
    /// reached via `KDBXContent.database.root.group`.
    struct Group: Sendable, Equatable {
        /// Stable identity for this group. Persists across renames, moves,
        /// and round-trips through the writer; the canonical reference
        /// when something else (an entry's ``Entry/previousParentGroup``,
        /// `Meta.recycleBinUUID`, etc.) needs to point at a group.
        public var uuid: UUID

        /// User-visible name of the folder. Optional per the KDBX 4.1
        /// XSD, but every real-world client sets one.
        public var name: String?

        /// Free-form notes attached to the folder itself (not to any
        /// entry inside it).
        public var notes: String?

        /// Standard icon index from KeePass's built-in icon set.
        /// See `Ext/Images_Client_HighRes` in the KeePass source for the
        /// numeric mapping. Use ``customIconUUID`` to override with a
        /// vault-embedded image.
        public var iconID: UInt32

        /// When non-nil, refers to an entry in `Meta.customIcons` and
        /// shadows ``iconID``. UI clients should prefer the custom icon
        /// whenever this is set.
        public var customIconUUID: UUID?

        /// Creation, last-modification, last-access timestamps, plus the
        /// expiry hint. Optional because legacy 3.x clients sometimes
        /// omit it; modern saves always populate it.
        public var times: Times?

        /// UI hint: whether the group node is shown expanded in the
        /// client's tree view. Not security-relevant.
        public var isExpanded: Bool?

        /// Default auto-type keystroke sequence inherited by entries in
        /// this group (and its subgroups) that don't override it. See
        /// <https://keepass.info/help/base/autotype.html>.
        public var defaultAutoTypeSequence: String?

        /// Tri-state auto-type policy. `nil` means "inherit from parent
        /// group"; `false` disables auto-type for the entire subtree
        /// regardless of per-entry settings.
        public var enableAutoType: NullableBoolEx?

        /// Tri-state search policy. `nil` means "inherit from parent
        /// group"; `false` hides the subtree from search results.
        public var enableSearching: NullableBoolEx?

        /// UUID of whichever entry was scrolled to the top when this
        /// group was last viewed. UI hint, not security-relevant.
        public var lastTopVisibleEntry: UUID?

        /// UUID of the group this group was last nested under. Updated
        /// whenever this group's parent changes — moving between
        /// folders, sending to the recycle bin, restoring from it.
        /// Hosts use it to offer "move back" / restore-from-bin
        /// affordances; clients are also free to ignore it.
        public var previousParentGroup: UUID?

        /// User-applied tags on the group. The KDBX 4.1 XSD specifies
        /// `;`-separated on disk; the reader accepts either `;` or `,`,
        /// and the writer emits `,` to match KeePassXC's preferred
        /// form. Tag values containing `;` or `,` round-trip lossily.
        /// See <https://keepass.info/help/v2/entry.html#tags>.
        public var tags: [String]

        /// Arbitrary string key/value pairs hosts can attach to the
        /// group. Persisted on save; not surfaced by the KeePass UI
        /// by default. Use this for app-specific metadata.
        public var customData: [CustomDataItem]

        /// Records directly inside this folder. Does not include
        /// entries nested in subgroups — use ``KDBX/visitEntries(in:_:)``
        /// for a recursive walk.
        public var entries: [Entry]

        /// Nested subfolders.
        public var groups: [Group]

        public init(
            uuid: UUID,
            name: String? = nil,
            notes: String? = nil,
            iconID: UInt32 = 0,
            customIconUUID: UUID? = nil,
            times: Times? = nil,
            isExpanded: Bool? = nil,
            defaultAutoTypeSequence: String? = nil,
            enableAutoType: NullableBoolEx? = nil,
            enableSearching: NullableBoolEx? = nil,
            lastTopVisibleEntry: UUID? = nil,
            previousParentGroup: UUID? = nil,
            tags: [String] = [],
            customData: [CustomDataItem] = [],
            entries: [Entry] = [],
            groups: [Group] = []
        ) {
            self.uuid = uuid
            self.name = name
            self.notes = notes
            self.iconID = iconID
            self.customIconUUID = customIconUUID
            self.times = times
            self.isExpanded = isExpanded
            self.defaultAutoTypeSequence = defaultAutoTypeSequence
            self.enableAutoType = enableAutoType
            self.enableSearching = enableSearching
            self.lastTopVisibleEntry = lastTopVisibleEntry
            self.previousParentGroup = previousParentGroup
            self.tags = tags
            self.customData = customData
            self.entries = entries
            self.groups = groups
        }
    }
}
