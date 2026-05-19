//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

/// The vault data tree — everything that's "inside" a KDBX file once
/// it's been unlocked and decrypted.
///
/// A `KDBX` value carries vault metadata (``Meta``) and the entry/group
/// hierarchy rooted at ``Root/group``. Walk the tree with
/// ``visitEntries(in:_:)`` / ``visitGroups(in:_:)``, or recurse manually
/// via `group.entries` and `group.groups`. Mutating entries and groups
/// is a straightforward in-place struct mutation; the parent
/// ``KDBXContent`` is what you pass to ``KDBXWriter`` when saving.
public struct KDBX: Sendable, Equatable {
    /// Vault-level metadata: name, description, custom data, default
    /// username, recycle-bin pointer, timestamps for various
    /// "settings changed" events, KeePass UI hints, etc.
    public var meta: Meta

    /// The root of the group tree. KDBX has a single top-level
    /// `Root` that contains exactly one `group`; user-visible groups
    /// nest under that one.
    public var root: Root

    public init(meta: Meta, root: Root) {
        self.meta = meta
        self.root = root
    }
}

public extension KDBX {
    /// Walk every entry under `group`, depth-first, calling `visitor`
    /// once per entry. Recurses into nested subgroups.
    func visitEntries(
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

    /// Walk every group under (and including) `group`, depth-first.
    /// `visitor` is called with the supplied root first, then with each
    /// descendant. Entries are not visited — use ``visitEntries(in:_:)``
    /// for that.
    func visitGroups(
        in group: KDBX.Group,
        _ visitor: (KDBX.Group) -> Void
    ) {
        visitor(group)

        for group in group.groups {
            visitGroups(in: group, visitor)
        }
    }
}
