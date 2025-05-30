//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Testing
import Foundation

@testable import KDBXKit

struct VariantDictionaryTests {
    @Test
    func formatVersion_1_0() {
        let version = VariantDictionary.FormatVersion(rawValue: 0x0100)
        #expect(version.major == 1)
        #expect(version.minor == 0)
        #expect(version == .v1_0)
        #expect(version.rawValue == 0x0100)
    }

    @Test
    func writeThenRead() async throws {
        var vardict = VariantDictionary()
        vardict["A"] = .boolean(true)
        vardict["B"] = .boolean(false)
        vardict["C"] = .int32(-424242)
        vardict["D"] = .uint32(4242)
        vardict["E"] = .int64(-4242424242)
        vardict["F"] = .uint64(42424242)
        vardict["G"] = .string("Hello world")
        vardict["H"] = .bytes(Data([1, 2, 3, 4]))

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try VariantDictionaryWriter(to: outputStream).write(vardict)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        let parsed = try VariantDictionaryReader(data: data).parse()

        #expect(parsed == vardict)
    }
}
