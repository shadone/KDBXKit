//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the full KDBXReader.parse pipeline. A deliberately
// tiny KDFParameterLimits makes any input declaring real KDF cost throw
// kdfParametersOutOfRange immediately, so the engine spends its time in the
// parser rather than the KDF. Safety in production comes from the library's
// .default limits, not from this clamp.

import Foundation
import KDBXKit

private let unlock = UnlockData(masterPassword: "fuzz")
private let tinyLimits = KDFParameterLimits(
    maxArgon2Memory: 1 << 20, // 1 MiB
    maxArgon2Iterations: 2,
    maxArgon2Parallelism: 2,
    maxAESKDFRounds: 10000
)

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    _ = try? KDBXReader.parse(data, unlockData: unlock, kdfLimits: tinyLimits)
    return 0
}
