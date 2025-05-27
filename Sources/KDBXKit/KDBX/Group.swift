//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    //  This is actually unordered except for the Entry and Group child elements, where the order matters.
    struct Group: Sendable {
        var uuid: UUID

        var name: String?

        var notes: String?

        /// See the folder "Ext/Images_Client_HighRes" in the KeePass source code package.
        var iconID: UInt32

        /// Reference to a custom icon stored in the KeePassFile/Meta/CustomIcons element. If non-zero, it overrides IconID.
        var customIconUUID: UUID?

        var times: Times?

        /// Specifies whether the group is displayed as expanded in the user interface.
        var isExpanded: Bool?

        var defaultAutoTypeSequence: String?

        var enableAutoType: NullableBoolEx?

        var enableSearching: NullableBoolEx?

        var lastTopVisibleEntry: UUID?

        /// UUID of the group in which the current group was stored previously. This information can for instance be used by a recycle bin restoration command.
        var previousParentGroup: UUID?

        /// Tags associated with the group, separated using ';'. https://keepass.info/help/v2/entry.html#tags
        var tags: [String]?

        var customData: [CustomDataItem]?

        var entries: [Entry]?

        var groups: [Group]?
    }
}
