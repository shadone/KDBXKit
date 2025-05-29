//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// The value type of the ``VariantDictionary``
public enum VariantDictionaryValue: Sendable, Equatable {
    case uint32(UInt32)
    case uint64(UInt64)
    case boolean(Bool)
    case int32(Int32)
    case int64(Int64)
    case string(String)
    case bytes(Data)
}

/// A name-value dictionary, where the name is a string and the type of the value depends on the item.
public typealias VariantDictionary = [String: VariantDictionaryValue]
