//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX.Meta {
    /// Mark Meta as having changed. Bumps `settingsChanged` to `time`.
    ///
    /// Pair with every mutation of a Meta field — KDBX-compatible
    /// clients read `SettingsChanged` to decide which side of a sync
    /// is fresher, so a stale value here silently loses real edits to
    /// a stale-but-fresher-looking remote copy. Field-specific
    /// `*Changed` companions (`databaseNameChanged`,
    /// `recycleBinChanged`, ...) still need to be set by the caller;
    /// `touch` only handles the umbrella timestamp.
    mutating func touch(at time: Date = Date()) {
        settingsChanged = time
    }
}
