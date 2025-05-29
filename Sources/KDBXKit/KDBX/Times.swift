//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    public struct Times: Sendable, Equatable {
        public var creationTime: Date?

        public var lastModificationTime: Date?

        /// In general, last access times are not reliable, because an access is not considered to be a database change. See the UIFlags value 0x20000: https://keepass.info/help/v2_dev/customize.html#uiflags
        public var lastAccessTime: Date?

        public var expiryTime: Date?

        public var expires: Bool?

        /// Cf. LastAccessTime.
        public var usageCount: UInt64?

        /// Last date/time when the object has been moved (within its parent group or to a different group). This is used by the synchronization algorithm to determine the latest location of the object.
        public var locationChanged: Date?
    }
}
