//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct CustomIcon: Sendable, Equatable {
        public let uuid: UUID
        public let data: Data
        public let name: String?
        public let lastModificationTime: Date?

        public init(uuid: UUID, data: Data, name: String?, lastModificationTime: Date?) {
            self.uuid = uuid
            self.data = data
            self.name = name
            self.lastModificationTime = lastModificationTime
        }
    }
}
