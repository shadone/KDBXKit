//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoSwift
import Foundation

/// The content of the `.kdbx` file.
public struct KDBXContent: Equatable {
    public var database: KDBX
    public let header: Header
    public let innerHeader: InnerHeader
}
