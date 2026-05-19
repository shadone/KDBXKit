//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A plain string key/value pair attached to a group or entry.
    ///
    /// Host apps and KeePass plugins use ``Group/customData`` /
    /// ``Entry/customData`` to attach app-specific metadata that
    /// survives saves but isn't surfaced by the standard KeePass UI.
    /// The KDBX spec recommends namespacing keys to avoid collisions
    /// — typically `AppName_FieldName` or `vendor:key`.
    ///
    /// At vault level, ``Meta/customData`` uses the richer
    /// ``CustomDataWithTimes`` variant which also carries a
    /// per-item modification timestamp.
    struct CustomDataItem: Sendable, Equatable {
        /// Item key. Should be unique within the parent's
        /// `customData` array; the spec recommends prefixing with an
        /// app or plugin name (e.g. `PluginName_ItemName`).
        public var key: String

        /// Item value. Plain `String` — no protected-in-memory
        /// treatment. Don't put secrets here.
        public var value: String
    }
}
