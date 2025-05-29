//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    //  This is actually unordered except for the Entry and Group child elements, where the order matters.
    public struct Group: Sendable {
        public var uuid: UUID

        public var name: String?

        public var notes: String?

        /// See the folder "Ext/Images_Client_HighRes" in the KeePass source code package.
        public var iconID: UInt32

        /// Reference to a custom icon stored in the KeePassFile/Meta/CustomIcons element. If non-zero, it overrides IconID.
        public var customIconUUID: UUID?

        public var times: Times?

        /// Specifies whether the group is displayed as expanded in the user interface.
        public var isExpanded: Bool?

        public var defaultAutoTypeSequence: String?

        public var enableAutoType: NullableBoolEx?

        public var enableSearching: NullableBoolEx?

        public var lastTopVisibleEntry: UUID?

        /// UUID of the group in which the current group was stored previously. This information can for instance be used by a recycle bin restoration command.
        public var previousParentGroup: UUID?

        /// Tags associated with the group, separated using ';'. https://keepass.info/help/v2/entry.html#tags
        public var tags: [String]

        public var customData: [CustomDataItem]

        public var entries: [Entry]

        public var groups: [Group]

        public init(
            uuid: UUID,
            name: String? = nil,
            notes: String? = nil,
            iconID: UInt32 = 0,
            customIconUUID: UUID? = nil,
            times: Times? = nil,
            isExpanded: Bool? = nil,
            defaultAutoTypeSequence: String? = nil,
            enableAutoType: NullableBoolEx? = nil,
            enableSearching: NullableBoolEx? = nil,
            lastTopVisibleEntry: UUID? = nil,
            previousParentGroup: UUID? = nil,
            tags: [String] = [],
            customData: [CustomDataItem] = [],
            entries: [Entry] = [],
            groups: [Group] = []
        ) {
            self.uuid = uuid
            self.name = name
            self.notes = notes
            self.iconID = iconID
            self.customIconUUID = customIconUUID
            self.times = times
            self.isExpanded = isExpanded
            self.defaultAutoTypeSequence = defaultAutoTypeSequence
            self.enableAutoType = enableAutoType
            self.enableSearching = enableSearching
            self.lastTopVisibleEntry = lastTopVisibleEntry
            self.previousParentGroup = previousParentGroup
            self.tags = tags
            self.customData = customData
            self.entries = entries
            self.groups = groups
        }
    }
}
