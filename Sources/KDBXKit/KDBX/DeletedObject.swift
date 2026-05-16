//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct DeletedObject: Sendable, Equatable {
        public let uuid: UUID
        public let deletionTime: Date

        public init(uuid: UUID, deletionTime: Date) {
            self.uuid = uuid
            self.deletionTime = deletionTime
        }
    }
}
