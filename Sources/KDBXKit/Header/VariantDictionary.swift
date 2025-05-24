//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public enum VariantDictionaryValue: Sendable {
    case uint32(UInt32)
    case uint64(UInt64)
    case boolean(Bool)
    case int32(Int32)
    case int64(Int64)
    case string(String)
    case bytes(Data)
}

public typealias VariantDictionary = [String: VariantDictionaryValue]
