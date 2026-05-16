//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The content of the `.kdbx` file.
public struct KDBXContent: Equatable, Sendable {
    public var database: KDBX
    public var header: Header
    public var innerHeader: InnerHeader

    /// Diagnostics emitted by the XML parser during the most recent parse:
    /// unknown elements and attributes that were silently dropped, malformed
    /// values that were tolerated, etc. Useful as a regression net for
    /// detecting data loss when reading files produced by other KDBX-aware
    /// tools (KeePass, KeePassXC, Strongbox, etc.).
    ///
    /// Empty for files produced by `KDBXWriter` against the current model.
    public var parserWarnings: [String]

    public init(
        database: KDBX,
        header: Header,
        innerHeader: InnerHeader,
        parserWarnings: [String] = []
    ) {
        self.database = database
        self.header = header
        self.innerHeader = innerHeader
        self.parserWarnings = parserWarnings
    }
}
