//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing

@testable import KDBXKit

struct InnerHeaderTests {
    @Test
    func writeThenRead() async throws {
        let innerHeader = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: Data([1, 2, 3, 4]),
            binaryContent: [
                .init(shouldBeProtected: false, data: Data([2, 3, 4])),
                .init(shouldBeProtected: true, data: Data([7, 8, 9])),
            ],
        )

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try InnerHeaderWriter(to: outputStream).write(innerHeader)
        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

        var reader = InnerHeaderReader(data: data)
        let (parsed, innerHeaderLength) = try reader.parse()

        #expect(parsed == innerHeader)
        #expect(innerHeaderLength == data.count)
    }
}
