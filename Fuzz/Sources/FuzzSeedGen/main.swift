//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// Generates seed-corpus inputs for the libFuzzer targets that fuzz
// post-decryption parsers. Currently emits a decrypted XML document for the
// FuzzXML target — a real, structurally-valid KDBX XML body gives the XML
// fuzzer a far richer starting point than an empty corpus.
//
// Usage: FuzzSeedGen <fixture.kdbx> <password> <corpus-root>
// Writes <corpus-root>/xml/seed-fixture.xml.

import Foundation
import KDBXKit

let args = CommandLine.arguments
guard args.count == 4 else {
    FileHandle.standardError.write(Data("usage: FuzzSeedGen <fixture.kdbx> <password> <corpus-root>\n".utf8))
    exit(2)
}

let fixturePath = args[1]
let password = args[2]
let corpusRoot = URL(fileURLWithPath: args[3])

let data: Data
do {
    data = try Data(contentsOf: URL(fileURLWithPath: fixturePath))
} catch {
    FileHandle.standardError.write(Data("error: cannot read fixture \(fixturePath): \(error)\n".utf8))
    exit(1)
}

var reader = KDBXReader(data)
do {
    _ = try reader.parse(unlockData: UnlockData(masterPassword: password), retainsXMLForDiagnostics: true)
} catch {
    FileHandle.standardError.write(Data("error: failed to unlock fixture: \(error)\n".utf8))
    exit(1)
}

guard let xml = reader.xmlDocument else {
    FileHandle.standardError.write(Data("error: reader did not retain XML\n".utf8))
    exit(1)
}

let xmlDir = corpusRoot.appendingPathComponent("xml")
do {
    try FileManager.default.createDirectory(at: xmlDir, withIntermediateDirectories: true)
    let dst = xmlDir.appendingPathComponent("seed-fixture.xml")
    try Data(xml.utf8).write(to: dst)
    print("wrote XML seed (\(xml.utf8.count) bytes) -> \(dst.path)")
} catch {
    FileHandle.standardError.write(Data("error: cannot write seed: \(error)\n".utf8))
    exit(1)
}
