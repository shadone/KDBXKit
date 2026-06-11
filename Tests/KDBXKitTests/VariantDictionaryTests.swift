//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing

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
        vardict["C"] = .int32(-424_242)
        vardict["D"] = .uint32(4242)
        vardict["E"] = .int64(-4_242_424_242)
        vardict["F"] = .uint64(42_424_242)
        vardict["G"] = .string("Hello world")
        vardict["H"] = .bytes(Data([1, 2, 3, 4]))

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try VariantDictionaryWriter(to: outputStream).write(vardict)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        let parsed = try VariantDictionaryReader(data: data).parse()

        #expect(parsed == vardict)
    }

    /// Regression: the reader must index `data` by absolute `Data.Index`
    /// throughout. `readUInt8` previously mixed offset-from-`startIndex`
    /// addressing with `readData`'s absolute addressing and a `count`-based
    /// bounds check, so it only parsed correctly for a zero-based `Data`.
    /// Feed a non-zero-based slice (startIndex == 2) and require an
    /// identical parse.
    @Test
    func parsesNonZeroBasedSlice() throws {
        var vardict = VariantDictionary()
        vardict["A"] = .boolean(true)
        vardict["D"] = .uint32(4242)
        vardict["G"] = .string("Hello world")
        vardict["H"] = .bytes(Data([1, 2, 3, 4]))

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try VariantDictionaryWriter(to: outputStream).write(vardict)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        // Prepend two bytes then drop them: `Data.SubSequence` is `Data`, so
        // the result shares storage and carries a non-zero `startIndex`.
        let slice = (Data([0xAA, 0xBB]) + data).dropFirst(2)
        #expect(slice.startIndex == 2)

        let parsed = try VariantDictionaryReader(data: slice).parse()
        #expect(parsed == vardict)
    }
}
