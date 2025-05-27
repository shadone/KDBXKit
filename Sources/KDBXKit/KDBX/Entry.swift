//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    // This is actually unordered except for the String, Binary and History child elements, where the order matters.
    struct Entry: Sendable {
        var uuid: UUID

        /// See the folder "Ext/Images_Client_HighRes" in the KeePass source code package.
        var iconID: UInt32

        /// Reference to a custom icon stored in the KeePassFile/Meta/CustomIcons element. If non-zero, it overrides IconID.
        var customIconUUID: UUID?

        var foregroundColor: Color?

        var backgroundColor: Color?

        /// https://keepass.info/help/base/autourl.html#override
        var overrideURL: String?

        /// https://keepass.info/help/v2/entry.html#gen
        /// https://keepass.info/help/kb/pw_quality_est.html
        var qualityCheck: Bool?

        /// Tags associated with the entry, separated using ';'. https://keepass.info/help/v2/entry.html#tags
        var tags: [String]?

        /// UUID of the group in which the current group was stored previously. This information can for instance be used by a recycle bin restoration command.
        var previousParentGroup: UUID?

        var times: Times?

        var strings: [ProtectedString]?

        var binaries: [ProtectedBinary]?

        var autoType: AutoType?

        var customData: [CustomDataItem]?

        /// https://keepass.info/help/v2/entry.html#hst
        var history: [Entry]?
    }
}
