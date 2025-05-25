//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    struct CustomDataWithTimes: Sendable {
        let customDataItem: CustomDataItem
        let lastModificationTime: Date?
    }
}
