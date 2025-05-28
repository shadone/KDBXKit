//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    public enum ValueOrNever<T: Sendable>: Sendable {
        case value(T)
        case never
    }
}
