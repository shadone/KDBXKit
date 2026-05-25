//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the header VariantDictionary reader.

import Foundation
@testable import KDBXKit

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    let reader = VariantDictionaryReader(data: data)
    _ = try? reader.parse()
    return 0
}
