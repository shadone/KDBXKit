//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    /// Allowed values in XML:
    ///
    /// - Null
    /// - null
    /// - False
    /// - false
    /// - True
    /// - true
    public enum NullableBoolEx: Sendable {
        case value(Bool)
        case null
    }
}
