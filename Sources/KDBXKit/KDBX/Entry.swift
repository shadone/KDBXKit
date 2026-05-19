//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A single record in the vault — credential, login, note, or
    /// whatever shape your host app exposes on top of KDBX's
    /// key/value field model.
    ///
    /// The actual data lives in ``strings`` (named text-shaped fields,
    /// including standard `Title` / `UserName` / `Password` / `URL` /
    /// `Notes` plus any custom strings) and ``binaries`` (file
    /// attachments). The rest of the struct is metadata: identity,
    /// display hints, behavior toggles, and an audit history.
    ///
    /// Find a specific field by key:
    ///
    /// ```swift
    /// let password = entry.strings.first(where: { $0.key == "Password" })?.value
    /// password?.withRevealedString { plaintext in
    ///     // plaintext lives only for this closure.
    /// }
    /// ```
    struct Entry: Sendable, Equatable {
        /// Stable identity for this entry. Persists across edits,
        /// history snapshots, group moves, and round-trips through the
        /// writer; the canonical reference for "the same entry" across
        /// vault versions.
        public var uuid: UUID

        /// Standard icon index from KeePass's built-in icon set.
        /// See `Ext/Images_Client_HighRes` in the KeePass source for
        /// the numeric mapping. Use ``customIconUUID`` to override
        /// with a vault-embedded image.
        public var iconID: UInt32

        /// When non-nil, refers to an entry in `Meta.customIcons` and
        /// shadows ``iconID``. UI clients should prefer the custom icon
        /// whenever this is set.
        public var customIconUUID: UUID?

        /// Display foreground color hint for the UI (text). Not
        /// security-relevant; clients are free to ignore it.
        public var foregroundColor: Color?

        /// Display background color hint for the UI. Not
        /// security-relevant; clients are free to ignore it.
        public var backgroundColor: Color?

        /// When non-nil, the UI uses this URL instead of the entry's
        /// `URL` field for "open" actions. Useful for protocol-scheme
        /// overrides (e.g. launching a custom handler).
        /// See <https://keepass.info/help/base/autourl.html#override>.
        public var overrideURL: String?

        /// When non-nil and `false`, the UI skips password-quality
        /// estimation for this entry. Useful for entries with
        /// intentionally weak passwords (service-account placeholders,
        /// shared throwaway accounts). `nil` means "use the host's
        /// default policy".
        /// See <https://keepass.info/help/v2/entry.html#gen> and
        /// <https://keepass.info/help/kb/pw_quality_est.html>.
        public var qualityCheck: Bool?

        /// User-applied tags on the entry. The KDBX 4.1 XSD specifies
        /// `;`-separated on disk; the reader accepts either `;` or `,`,
        /// and the writer emits `,` to match KeePassXC's preferred
        /// form. Tag values containing `;` or `,` round-trip lossily.
        /// See <https://keepass.info/help/v2/entry.html#tags>.
        public var tags: [String]

        /// UUID of the group this entry was last moved out of. Updated
        /// whenever the entry's parent group changes — moving between
        /// folders, sending to the recycle bin, restoring from it.
        /// Hosts use it to offer "move back" / restore-from-bin
        /// affordances; clients are also free to ignore it.
        public var previousParentGroup: UUID?

        /// Creation, last-modification, last-access timestamps, plus
        /// the expiry hint.
        public var times: Times?

        /// The entry's named text-shaped fields. Standard fields
        /// (`"Title"`, `"UserName"`, `"Password"`, `"URL"`, `"Notes"`)
        /// and any custom strings live in the same array, keyed by
        /// `ProtectedString.key`. Values are ``ProtectedString/Value``
        /// — reveal cleartext via
        /// ``ProtectedString/Value/withRevealedString(_:)``.
        public var strings: [ProtectedString]

        /// File attachments embedded on the entry. Each
        /// ``ProtectedBinary`` carries a reference into the vault's
        /// binary pool (in ``InnerHeader``), not the bytes themselves —
        /// the pool deduplicates byte-identical attachments across
        /// entries.
        public var binaries: [ProtectedBinary]

        /// Auto-type configuration: default keystroke sequence plus
        /// per-window-title associations. `nil` if auto-type is
        /// disabled or unset for this entry; consult
        /// ``Group/enableAutoType`` for the inherited policy.
        public var autoType: AutoType?

        /// Arbitrary string key/value pairs hosts can attach to the
        /// entry. Persisted on save; not surfaced by the KeePass UI
        /// by default. Use this for app-specific metadata (e.g.
        /// "last-synced-at" timestamps, source-system identifiers).
        public var customData: [CustomDataItem]

        /// Past versions of this entry, oldest first. Every `entry set`
        /// or equivalent edit prepends a snapshot of the prior state
        /// here. The list is trimmed on save according to
        /// `Meta.historyMaxItems`.
        /// See <https://keepass.info/help/v2/entry.html#hst>.
        public var history: [Entry]

        public init(
            uuid: UUID,
            iconID: UInt32 = 0,
            customIconUUID: UUID? = nil,
            foregroundColor: Color? = nil,
            backgroundColor: Color? = nil,
            overrideURL: String? = nil,
            qualityCheck: Bool? = nil,
            tags: [String] = [],
            previousParentGroup: UUID? = nil,
            times: Times? = nil,
            strings: [ProtectedString] = [],
            binaries: [ProtectedBinary] = [],
            autoType: AutoType? = nil,
            customData: [CustomDataItem] = [],
            history: [Entry] = []
        ) {
            self.uuid = uuid
            self.iconID = iconID
            self.customIconUUID = customIconUUID
            self.foregroundColor = foregroundColor
            self.backgroundColor = backgroundColor
            self.overrideURL = overrideURL
            self.qualityCheck = qualityCheck
            self.tags = tags
            self.previousParentGroup = previousParentGroup
            self.times = times
            self.strings = strings
            self.binaries = binaries
            self.autoType = autoType
            self.customData = customData
            self.history = history
        }
    }
}
