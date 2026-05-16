//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

public extension KDBX {
    /// Process memory protection settings, describing which standard fields should be protected. KeePass resets these settings to their default values after opening a database.
    struct MemoryProtectionConfig: Sendable, Equatable {
        public var protectTitle: Bool?
        public var protectUserName: Bool?
        public var protectPassword: Bool?
        public var protectURL: Bool?
        public var protectNotes: Bool?

        public init(
            protectTitle: Bool? = nil,
            protectUserName: Bool? = nil,
            protectPassword: Bool? = nil,
            protectURL: Bool? = nil,
            protectNotes: Bool? = nil
        ) {
            self.protectTitle = protectTitle
            self.protectUserName = protectUserName
            self.protectPassword = protectPassword
            self.protectURL = protectURL
            self.protectNotes = protectNotes
        }
    }
}
