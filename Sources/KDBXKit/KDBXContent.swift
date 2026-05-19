//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The decoded content of a `.kdbx` file — vault data tree, outer
/// header, and inner header, in one value type.
///
/// Returned from ``KDBXReader/parse(_:unlockData:)`` and consumed by
/// ``KDBXWriter/write(_:unlockData:regenerateSalts:)``. Mutate it like
/// any Swift struct (entries, groups, metadata are reachable through
/// `database.root.group`); the writer regenerates random salts and
/// IVs on every save unless explicitly opted out.
public struct KDBXContent: Equatable, Sendable {
    /// The vault data tree — groups, entries, metadata. The "what's
    /// in the vault" half of the file. Access entries via
    /// `database.root.group` and `database.visitEntries(in:_:)`.
    public var database: KDBX

    /// The outer file header — format version, cipher choice, KDF
    /// parameters, master salt, encryption nonce. The "how the file
    /// is wrapped" half. Mostly read-only from the caller's
    /// perspective; the writer re-derives most of it on save.
    public var header: Header

    /// The inner header — inner-stream cipher choice + its key, plus
    /// the binary attachment pool. Decrypted from inside the outer
    /// encrypted block stream.
    public var innerHeader: InnerHeader

    /// Diagnostics emitted by the XML parser during the most recent parse:
    /// unknown elements and attributes that were silently dropped, malformed
    /// values that were tolerated, etc. Useful as a regression net for
    /// detecting data loss when reading files produced by other KDBX-aware
    /// tools (KeePass, KeePassXC, Strongbox, etc.).
    ///
    /// Empty for files produced by `KDBXWriter` against the current model.
    public var parserWarnings: [String]

    /// Notice that the on-disk format of this content does not match the
    /// format ``KDBXWriter`` will emit when this content is saved.
    ///
    /// Surfaced as a typed value (not a string) so UI layers can display
    /// it without parsing free-form parser warnings — pattern-match the
    /// enum and present the appropriate banner / confirmation. Always
    /// `nil` for files originally opened as KDBX 4.x.
    public var legacyFormatNotice: LegacyFormatNotice?

    /// Reasons the writer's output will differ from the content's
    /// on-disk source. Extensible — future cases might cover legacy
    /// inner ciphers, retired KDFs, or deprecated XML dialects.
    public enum LegacyFormatNotice: Sendable, Equatable {
        /// File was opened from a pre-KDBX-4 format (3.0 / 3.1). On
        /// save it will be re-serialized as KDBX 4.1 — the migration is
        /// one-way: ``KDBXWriter`` does not emit the 3.x on-disk shape.
        /// `originalVersion` is the file's version field at open time,
        /// suitable for messages like "This vault is in KDBX 3.1
        /// format; saving will upgrade it to KDBX 4.1."
        case willMigrate(from: Header.FormatVersion)
    }

    public init(
        database: KDBX,
        header: Header,
        innerHeader: InnerHeader,
        parserWarnings: [String] = [],
        legacyFormatNotice: LegacyFormatNotice? = nil
    ) {
        self.database = database
        self.header = header
        self.innerHeader = innerHeader
        self.parserWarnings = parserWarnings
        self.legacyFormatNotice = legacyFormatNotice
    }
}
