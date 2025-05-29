//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public struct Database: Sendable, Equatable {
    public var meta: KDBX.Meta
    public var root: KDBX.Root
}
