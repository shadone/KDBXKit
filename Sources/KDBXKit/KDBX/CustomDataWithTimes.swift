//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    public struct CustomDataWithTimes: Sendable {
        public var key: String
        public var value: String
        public var lastModificationTime: Date?
    }
}
