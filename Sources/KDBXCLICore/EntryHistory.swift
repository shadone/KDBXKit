//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// History bookkeeping for `entry set` and the explicit `entry history`
/// commands. KDBX stores prior versions of an entry inline under
/// `Entry.history: [Entry]`. The historical entries never carry their own
/// nested history — only the live entry does — which keeps growth linear
/// rather than quadratic.
enum EntryHistory {
    /// Append a copy of `entry`'s current state to its own history list,
    /// then trim by `Meta.historyMaxItems` if a finite cap is set. Call
    /// **before** mutating the live entry, so the snapshot captures what
    /// the entry used to look like.
    ///
    /// `historyMaxSize` (byte budget) is part of the spec but requires
    /// serializing each snapshot to weigh — deferred to a follow-up.
    static func snapshot(_ entry: inout KDBX.Entry, meta: KDBX.Meta) {
        var snapshot = entry
        // Historical entries do not carry their own history (spec).
        snapshot.history = []
        entry.history.append(snapshot)
        trim(&entry.history, against: meta.historyMaxItems)
    }

    /// Drop the oldest entries until the list fits under the cap. Returns
    /// the number of items dropped — caller can surface this if useful.
    @discardableResult
    static func trim(_ history: inout [KDBX.Entry], against cap: KDBX.ValueOrUnlimited<UInt32>?) -> Int {
        guard case let .value(maxItems) = cap else { return 0 }
        let limit = Int(maxItems)
        if history.count <= limit { return 0 }
        let drop = history.count - limit
        history.removeFirst(drop)
        return drop
    }
}
