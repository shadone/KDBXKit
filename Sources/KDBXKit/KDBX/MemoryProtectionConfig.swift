//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    /// Per-standard-field flags describing which entry strings the
    /// vault wants stored encrypted in memory (and on disk, via the
    /// inner stream cipher).
    ///
    /// Lives at ``Meta/memoryProtection``. Each flag controls one of
    /// the five standard string fields. The KeePass UI uses these as
    /// defaults when creating new entries — if `protectPassword` is
    /// `true`, new entries get their `Password` string stored as
    /// `Protected="True"` on disk.
    ///
    /// > Note: The KDBX spec notes that **KeePass resets these
    /// > settings to their default values** after opening a database.
    /// > In practice that means the on-disk values aren't always
    /// > reliable as a record of the user's preferences; treat them
    /// > as advisory.
    ///
    /// KDBXKit reads and writes the config verbatim — it doesn't
    /// reset, override, or otherwise interpret the flags.
    struct MemoryProtectionConfig: Sendable, Equatable {
        /// Whether the `Title` field should be protected by default.
        /// Most clients leave this `false`; titles are typically
        /// visible in the entry list.
        public var protectTitle: Bool?

        /// Whether the `UserName` field should be protected by
        /// default. Most clients leave this `false`.
        public var protectUserName: Bool?

        /// Whether the `Password` field should be protected by
        /// default. Most clients set this to `true` — passwords are
        /// the canonical secret field.
        public var protectPassword: Bool?

        /// Whether the `URL` field should be protected by default.
        /// Most clients leave this `false`.
        public var protectURL: Bool?

        /// Whether the `Notes` field should be protected by default.
        /// Vendor-specific — notes can carry secondary secrets
        /// (recovery codes, security questions), so some clients
        /// default to `true`.
        public var protectNotes: Bool?

        public init(
            protectTitle: Bool? = nil,
            protectUserName: Bool? = nil,
            protectPassword: Bool? = nil,
            protectURL: Bool? = nil,
            protectNotes: Bool? = nil
        ) {
            self.protectTitle = protectTitle
            self.protectUserName = protectUserName
            self.protectPassword = protectPassword
            self.protectURL = protectURL
            self.protectNotes = protectNotes
        }
    }
}
