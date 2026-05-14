//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The content of the `.kdbx` file.
public struct KDBXContent: Equatable, Sendable {
    public var database: KDBX
    public var header: Header
    public var innerHeader: InnerHeader

    public init(database: KDBX, header: Header, innerHeader: InnerHeader) {
        self.database = database
        self.header = header
        self.innerHeader = innerHeader
    }
}
