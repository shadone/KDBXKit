//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for KDBXReader.parseHeader. Asserts the header parser
// returns a typed error or a Header — never a trap, never a hang. A trap
// (force-unwrap / fatalError / OOB) crashes the process and libFuzzer captures
// the input; a typed throw is swallowed by `try?`.

import Foundation
import KDBXKit

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    _ = try? KDBXReader.parseHeader(data)
    return 0
}
