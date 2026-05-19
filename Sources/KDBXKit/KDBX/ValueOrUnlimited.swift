//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    /// A scalar with an explicit "unlimited" opt-out.
    ///
    /// Used by ``Meta/historyMaxItems`` and ``Meta/historyMaxSize`` —
    /// both are limits on per-entry history (count and byte budget,
    /// respectively) where the user can either set a number or
    /// disable trimming entirely. KDBX 4 represents the opt-out as a
    /// sentinel on the wire; `.unlimited` is the typed form of that.
    enum ValueOrUnlimited<T: Sendable & Equatable>: Sendable, Equatable {
        /// An explicit limit — e.g. `value(10)` for "keep at most 10
        /// history snapshots per entry".
        case value(T)

        /// The "no limit" opt-out. The associated trimming policy
        /// doesn't fire.
        case unlimited
    }
}
