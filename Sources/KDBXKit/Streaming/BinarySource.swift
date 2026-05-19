//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// A pluggable source of binary attachment bytes for the streaming
/// write path. Each pool entry the writer emits asks its source to
/// stream bytes into a sink — the sink writes those bytes through the
/// gzip + encrypt + HMAC-block pipeline straight to the output file.
/// Sources are pulled one at a time, so peak in-process memory during
/// save is bounded by a single attachment's size (plus the encrypt /
/// HMAC-block working buffers), not the sum of all attachments.
public protocol BinarySource: Sendable {
    /// Total size of the payload in bytes — used by the writer to
    /// pre-size its working buffers and (where applicable) to drive
    /// progress reporting.
    var sizeBytes: Int { get }

    /// Whether the payload should be flagged as "protected in
    /// memory" on the receiving side — surfaces as
    /// ``InnerHeader/BinaryContent/shouldBeProtected`` on the
    /// written pool entry.
    var shouldBeProtected: Bool { get }

    /// Push every byte of this binary into `sink`. The streaming
    /// writer will call `finalize` on the sink itself after all
    /// sources for a write have been drained — implementations should
    /// NOT call `sink.finalize()`.
    func stream(into sink: inout some ByteSink) throws
}

/// Binary source backed by an in-memory `Data` — typical for new
/// attachments added since the vault was opened.
public struct DataBinarySource: BinarySource {
    /// In-memory payload bytes.
    public let data: Data

    /// Mirrors ``BinarySource/shouldBeProtected`` — pass `true` for
    /// secret-shaped attachments (recovery PDFs, key backups, etc.).
    public let shouldBeProtected: Bool

    public var sizeBytes: Int { data.count }

    /// - Parameters:
    ///   - data: in-memory payload to write.
    ///   - shouldBeProtected: whether the receiving pool entry
    ///     should be flagged "protected in memory". Defaults to
    ///     `false`; pass `true` for secret-shaped attachments.
    public init(_ data: Data, shouldBeProtected: Bool = false) {
        self.data = data
        self.shouldBeProtected = shouldBeProtected
    }

    public func stream(into sink: inout some ByteSink) throws {
        try data.withUnsafeBytes { buf in
            try sink.write(buf)
        }
    }
}

/// Binary source backed by a `LazyKDBXContent` — re-streams bytes
/// for a pool entry from the encrypted source file via
/// `KDBXReader.streamBinary`. Peak in-process memory during the
/// stream call is one decompression chunk (~64 KB) plus the bytes
/// the sink consumes.
public struct LazyBinarySource: BinarySource {
    /// The lazy reader the bytes will be re-streamed from. Holding
    /// this keeps the source vault accessible for the lifetime of
    /// the streaming write.
    public let lazyContent: LazyKDBXContent

    /// Position in ``LazyKDBXContent/binaries`` identifying which
    /// pool entry to stream.
    public let index: Int

    /// - Parameters:
    ///   - lazyContent: the source vault opened via
    ///     ``KDBXReader/openMetadataOnly(from:unlockData:maxDecompressedPayloadSize:)``.
    ///   - index: pool index to stream from
    ///     ``LazyKDBXContent/binaries``.
    public init(_ lazyContent: LazyKDBXContent, at index: Int) {
        self.lazyContent = lazyContent
        self.index = index
    }

    public var sizeBytes: Int {
        lazyContent.binaries.indices.contains(index)
            ? lazyContent.binaries[index].sizeBytes
            : 0
    }

    public var shouldBeProtected: Bool {
        lazyContent.binaries.indices.contains(index)
            ? lazyContent.binaries[index].isProtected
            : false
    }

    public func stream(into sink: inout some ByteSink) throws {
        try KDBXReader.streamBinary(from: lazyContent, at: index, into: &sink)
    }
}
