//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    enum ValueOrUnlimited<T: Sendable>: Sendable {
        case value(T)
        case unlimited
    }
}
