//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    /// A KDBX-spec tri-state bool: `value(true)`, `value(false)`, or
    /// `null` (meaning "inherit from parent").
    ///
    /// Used for group-level policy flags whose absence is meaningful
    /// rather than equivalent to `false` — ``Group/enableAutoType``
    /// and ``Group/enableSearching``, where `nil` means "follow the
    /// parent group's setting" rather than "auto-type is disabled".
    ///
    /// The on-disk XML representation accepts both
    /// title-case and lower-case spellings: `Null` / `null`,
    /// `True` / `true`, `False` / `false`. The writer emits the
    /// title-case form to match what KeePass 2 produces.
    enum NullableBoolEx: Sendable, Equatable {
        /// Explicit boolean — overrides any parent inheritance.
        case value(Bool)

        /// "Inherit from parent" — for group policy fields, defer to
        /// the enclosing group (or to the vault default if at the
        /// top level).
        case null
    }
}
