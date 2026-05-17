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
    var sizeBytes: Int { get }
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
    public let data: Data
    public let shouldBeProtected: Bool
    public var sizeBytes: Int { data.count }

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
    public let lazyContent: LazyKDBXContent
    public let index: Int

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
