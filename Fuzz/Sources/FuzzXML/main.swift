//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the post-decryption XML reader. Bypasses HMAC so
// the engine actually reaches XMLDocumentReader. A fixed keystream is fine —
// the reader only uses it to decrypt protected fields, and gibberish plaintext
// must not crash it.

import Foundation
@testable import KDBXKit

private let keystream = KeystreamSource(
    algorithm: .chacha20,
    key: SecureBytes(Data(repeating: 0, count: 32)),
    nonce: Data(repeating: 0, count: 12)
)

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    guard let xml = String(data: data, encoding: .utf8) else { return 0 }
    let reader = try? XMLDocumentReader(xmlDocument: xml, keystreamSource: keystream)
    _ = try? reader?.parse()
    return 0
}
