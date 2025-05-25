//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    //  This is actually unordered except for the Entry and Group child elements, where the order matters.
    struct Group: Sendable {
        let uuid: UUID

        let name: String?

        let notes: String?

        /// See the folder "Ext/Images_Client_HighRes" in the KeePass source code package.
        let iconID: UInt32

        /// Reference to a custom icon stored in the KeePassFile/Meta/CustomIcons element. If non-zero, it overrides IconID.
        let customIconUUID: UUID?

        let times: Times?

        /// Specifies whether the group is displayed as expanded in the user interface.
        let isExpanded: Bool?

        let defaultAutoTypeSequence: String?

        let enableAutoType: NullableBoolEx?

        let enableSearching: NullableBoolEx?

        let lastTopVisibleEntry: UUID?

        /// UUID of the group in which the current group was stored previously. This information can for instance be used by a recycle bin restoration command.
        let previousParentGroup: UUID?

        /// Tags associated with the group, separated using ';'. https://keepass.info/help/v2/entry.html#tags
        let tags: [String]?

        let customData: CustomDataItem?

        let entry: [Entry]?

        let group: [Group]?
    }
}
