//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct CustomDataWithTimes: Sendable, Equatable {
        public var key: String
        public var value: String
        public var lastModificationTime: Date?
    }
}
