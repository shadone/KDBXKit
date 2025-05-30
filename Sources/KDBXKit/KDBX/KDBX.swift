//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public struct KDBX: Sendable, Equatable {
    public var meta: Meta
    public var root: Root
}
