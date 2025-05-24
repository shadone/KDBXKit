//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

// https://keepass.info/help/kb/kdbx.html#vardict
enum VariantDictionaryValueType: UInt8 {
    case uint32 = 0x04
    case uint64 = 0x05
    case boolean = 0x08
    case int32 = 0x0C
    case int64 = 0x0D
    case string = 0x18
    case bytes = 0x42
}
