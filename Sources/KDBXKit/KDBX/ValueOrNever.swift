//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    enum ValueOrNever<T: Sendable & Equatable>: Sendable, Equatable {
        case value(T)
        case never
    }
}
