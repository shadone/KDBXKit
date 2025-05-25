//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension KDBX {
    /// Process memory protection settings, describing which standard fields should be protected. KeePass resets these settings to their default values after opening a database.
    struct MemoryProtectionConfig: Sendable {
        let protectTitle: Bool?
        let protectUserName: Bool?
        let protectPassword: Bool?
        let protectURL: Bool?
        let protectNotes: Bool?
    }
}
