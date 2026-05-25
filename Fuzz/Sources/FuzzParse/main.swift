//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// Placeholder — replaced by a later task with the real fuzz harness.

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    _ = start
    _ = count
    return 0
}
