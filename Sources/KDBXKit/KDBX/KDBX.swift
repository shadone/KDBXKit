//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public struct KDBX: Sendable, Equatable {
    public var meta: Meta
    public var root: Root
}

extension KDBX {
    public func visitEntries(
        in group: KDBX.Group,
        _ visitor: (KDBX.Entry) -> Void
    ) {
        for entry in group.entries {
            visitor(entry)
        }

        for group in group.groups {
            visitEntries(in: group, visitor)
        }
    }
}
