//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    public enum ValueOrUnlimited<T: Sendable & Equatable>: Sendable, Equatable {
        case value(T)
        case unlimited
    }
}
