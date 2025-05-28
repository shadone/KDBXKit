//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public struct Database: Sendable {
    var meta: KDBX.Meta
    var root: KDBX.Root
}
