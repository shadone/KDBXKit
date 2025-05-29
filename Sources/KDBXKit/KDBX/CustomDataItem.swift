//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension KDBX {
    /// Custom data item (key/value pair) for plugins/ports. The key should be unique, e.g. `PluginName_ItemName`.
    public struct CustomDataItem: Sendable, Equatable {
        public var key: String
        public var value: String
    }
}
