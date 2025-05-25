//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct CustomIcon: Sendable {
        let uuid: UUID
        let data: Data
        let name: String?
        let lastModificationTime: Date?
    }
}
