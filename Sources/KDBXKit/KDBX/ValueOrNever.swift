//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    /// A scalar with an explicit "never" opt-out.
    ///
    /// Used by ``Meta/masterKeyChangeRec`` and
    /// ``Meta/masterKeyChangeForce`` — both are day-count thresholds
    /// where the user can either set a number ("every 90 days") or
    /// opt out entirely. KDBX 4 represents the opt-out as a sentinel
    /// value on the wire; `.never` is the typed form of that.
    enum ValueOrNever<T: Sendable & Equatable>: Sendable, Equatable {
        /// An explicit value — e.g. `value(90)` for "every 90 days".
        case value(T)

        /// The "never" opt-out. The associated policy doesn't fire.
        case never
    }
}
