//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

/// The content of the `.kdbx` file.
public struct KDBXContent {
    public let database: Database
    public let header: Header
    public let innerHeader: InnerHeader
}
