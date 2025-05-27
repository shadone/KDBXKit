//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    /// Process memory protection settings, describing which standard fields should be protected. KeePass resets these settings to their default values after opening a database.
    struct MemoryProtectionConfig: Sendable {
        var protectTitle: Bool?
        var protectUserName: Bool?
        var protectPassword: Bool?
        var protectURL: Bool?
        var protectNotes: Bool?
    }
}
