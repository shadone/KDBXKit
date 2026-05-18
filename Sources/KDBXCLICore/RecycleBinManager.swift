//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Locate-or-create the recycle bin group. Returns nil if the vault has
/// explicitly opted out (`Meta.recycleBinEnabled == false`).
enum RecycleBinManager {
    /// KeePass uses icon ID 43 (RecycleBin) for the bin folder.
    static let recycleBinIconID: UInt32 = 43

    /// Ensure a usable recycle bin exists. Mutates `content` in place to
    /// adopt either an already-recorded bin UUID or a freshly-created one.
    /// Returns nil iff the vault has `recycleBinEnabled == false`, signaling
    /// to the caller that they should hard-delete instead.
    static func ensureBin(in content: inout KDBXContent, now: Date) -> UUID? {
        if content.database.meta.recycleBinEnabled == false {
            return nil
        }

        if let id = content.database.meta.recycleBinUUID,
           !id.isZeroUUID,
           TreeMutator.findGroup(uuid: id, in: content.database.root.group) != nil
        {
            return id
        }

        let binUUID = UUID()
        let bin = KDBX.Group(
            uuid: binUUID,
            name: "Recycle Bin",
            iconID: recycleBinIconID,
            times: KDBX.Times(
                creationTime: now,
                lastModificationTime: now,
                lastAccessTime: now,
                locationChanged: now
            ),
            enableAutoType: .value(false),
            enableSearching: .value(false)
        )
        content.database.root.group.groups.append(bin)
        // Assigning `recycleBinUUID` fires a `didSet` that bumps both
        // `recycleBinChanged` and `settingsChanged` — no explicit
        // companion writes needed.
        content.database.meta.recycleBinUUID = binUUID
        if content.database.meta.recycleBinEnabled == nil {
            content.database.meta.recycleBinEnabled = true
        }
        return binUUID
    }
}
