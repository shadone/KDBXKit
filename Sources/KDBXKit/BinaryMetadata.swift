//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Per-binary metadata captured during a lazy open. The actual bytes
/// are NOT retained on the metadata; use
/// `KDBXReader.streamBinary(from:at:into:)` to read them on demand.
///
/// `decompressedOffset` and `decompressedLength` locate the binary
/// payload within the decompressed inner-header stream — the lazy
/// reader uses them to seek during re-stream.
public struct BinaryMetadata: Sendable, Equatable {
    public let sizeBytes: Int
    public let isProtected: Bool
    /// SHA-256 of the binary payload. Computed once at open time so
    /// equality comparison (conflict detector, dedup) doesn't have to
    /// load the bytes.
    public let contentHash: Data

    let decompressedOffset: Int
    let decompressedLength: Int

    public init(
        sizeBytes: Int,
        isProtected: Bool,
        contentHash: Data,
        decompressedOffset: Int,
        decompressedLength: Int
    ) {
        self.sizeBytes = sizeBytes
        self.isProtected = isProtected
        self.contentHash = contentHash
        self.decompressedOffset = decompressedOffset
        self.decompressedLength = decompressedLength
    }
}
