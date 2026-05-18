//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import SwiftGzip

/// Inflates the per-`<Binary>` gzip payload used by the KDBX 3.x inline
/// binary pool (`<Meta><Binaries><Binary Compressed="True">...`).
///
/// Inflation is capped at the same ceiling as the outer KDBX payload —
/// pathological binaries that would otherwise inflate without bound fail
/// mid-inflate rather than allocating unbounded memory.
enum LegacyBinaryDecompressor {
    enum Error: Swift.Error {
        case decompressionFailed(reason: String)
        case decompressedPayloadTooLarge(limit: Int)
    }

    static func gunzip(
        _ data: Data,
        maxDecompressedPayloadSize: Int = KDBXReader.maxDecompressedPayloadSize
    ) throws(Error) -> Data {
        let input = InputStream(data: data)
        let output = CappedDataOutputStream(cap: maxDecompressedPayloadSize)
        do {
            try GzipDecompressor().unzip(inputStream: input, outputStream: output)
        } catch {
            if output.overflowed {
                throw .decompressedPayloadTooLarge(limit: maxDecompressedPayloadSize)
            }
            throw .decompressionFailed(reason: "\(error)")
        }
        return output.collected
    }
}
