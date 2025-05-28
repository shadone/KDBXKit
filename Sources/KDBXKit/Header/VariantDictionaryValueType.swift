//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

/// A variant dictionary is a name-value dictionary, where the name is a string and the type of the value depends on the item.
/// ```
/// 1. Format version, as UInt16.
///    a. The high byte is the major version. It is critical, i.e. an application must refuse to load the file if the major version is unsupported.
///    b. The low byte is the minor version. It can be ignored, but when encountering an unsupported value type, a confirmation/warning should be displayed or loading should fail.
///   The current version is 1.0, i.e. 0x0100.
/// 2. Zero or more items (see below).
/// 3. Null terminator byte.
/// ```
///
/// Each item is stored like this:
///
/// ```
/// <Value type (UInt8)> || <Name size (Int32)> || <Name (utf-8 string)> || <Value size (Int32)> || <Value>
/// ```
///
/// https://keepass.info/help/kb/kdbx.html#vardict
enum VariantDictionaryValueType: UInt8 {
    case uint32 = 0x04
    case uint64 = 0x05
    case boolean = 0x08
    case int32 = 0x0C
    case int64 = 0x0D
    case string = 0x18
    case bytes = 0x42
}
