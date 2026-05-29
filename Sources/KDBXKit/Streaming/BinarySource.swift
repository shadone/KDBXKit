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

/// Shared, decrypt-once cache for a streaming write that re-streams
/// many binaries from the SAME `LazyKDBXContent` (the typical
/// re-save of a vault whose attachments are mostly unchanged).
///
/// Pass one cache to every ``LazyBinarySource`` in a single write and
/// the source bytes are sliced from a single decrypt of the file.
/// Without it, each `LazyBinarySource.stream` calls
/// ``KDBXReader/streamBinary(from:at:into:)``, which re-reads +
/// re-decrypts + re-decompresses the WHOLE file — so a write of K
/// lazy binaries is O(K × file_size) (a multi-minute stall on a large
/// attachment-heavy vault).
///
/// - important: The cache holds the decompressed payload (every
///   binary's plaintext) for its lifetime. This trades the streaming
///   writer's "one attachment resident at a time" memory bound for a
///   single decrypt — the same plaintext-resident profile the eager
///   `serializeVault` path already has. Scope the cache to one write
///   (the save plan that owns the sources) so the payload is released
///   when the write completes. A gzip stream is not randomly
///   addressable, so resolving binaries pulled in arbitrary pool
///   order without re-decrypting requires holding the decompressed
///   bytes; a bounded-memory alternative would need the writer to
///   consume binaries in source-file offset order.
public final class LazyBinaryCache: @unchecked Sendable {
    private let lazyContent: LazyKDBXContent
    private let lock = NSLock()
    /// Memoized decompressed payload. Computed on first `bytes(at:)`,
    /// so a write with no lazy sources never decrypts.
    private var payload: Data?

    public init(_ lazyContent: LazyKDBXContent) {
        self.lazyContent = lazyContent
    }

    /// Bytes for one pool index, sliced from the single cached
    /// decrypt. The returned `Data` is a view onto the cached payload.
    func bytes(at index: Int) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        let resident: Data
        if let payload {
            resident = payload
        } else {
            resident = try KDBXReader.decryptWholePayload(of: lazyContent).payload
            payload = resident
        }
        return try KDBXReader.binarySlice(at: index, in: resident, binaries: lazyContent.binaries)
    }
}

/// Binary source backed by a `LazyKDBXContent` — re-streams bytes
/// for a pool entry from the encrypted source file.
///
/// - important: When more than one `LazyBinarySource` from the same
///   `LazyKDBXContent` is used in a single write, pass a shared
///   ``LazyBinaryCache`` (see ``init(_:at:cache:)``). Without one,
///   each source decrypts the whole file independently — O(sources ×
///   file_size). With a cache, all sources slice from a single
///   decrypt.
public struct LazyBinarySource: BinarySource {
    /// The lazy reader the bytes will be re-streamed from. Holding
    /// this keeps the source vault accessible for the lifetime of
    /// the streaming write.
    public let lazyContent: LazyKDBXContent

    /// Position in ``LazyKDBXContent/binaries`` identifying which
    /// pool entry to stream.
    public let index: Int

    /// Optional shared decrypt cache. When set, `stream` slices from
    /// the cache's single decrypt instead of re-decrypting the file.
    let cache: LazyBinaryCache?

    /// - Parameters:
    ///   - lazyContent: the source vault opened via
    ///     ``KDBXReader/openMetadataOnly(from:unlockData:maxDecompressedPayloadSize:)``.
    ///   - index: pool index to stream from
    ///     ``LazyKDBXContent/binaries``.
    public init(_ lazyContent: LazyKDBXContent, at index: Int) {
        self.init(lazyContent, at: index, cache: nil)
    }

    /// - Parameters:
    ///   - lazyContent: the source vault.
    ///   - index: pool index to stream from
    ///     ``LazyKDBXContent/binaries``.
    ///   - cache: a shared ``LazyBinaryCache`` so multiple sources from
    ///     the same vault decrypt the file once total instead of once
    ///     each. Pass the same instance to every lazy source in a
    ///     write.
    public init(_ lazyContent: LazyKDBXContent, at index: Int, cache: LazyBinaryCache?) {
        self.lazyContent = lazyContent
        self.index = index
        self.cache = cache
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
        guard let cache else {
            try KDBXReader.streamBinary(from: lazyContent, at: index, into: &sink)
            return
        }
        // Cached path: slice from the shared single decrypt and feed
        // the sink in chunks. Do NOT finalize — per the `BinarySource`
        // contract the streaming writer finalizes the sink itself.
        let bytes = try cache.bytes(at: index)
        let chunkSize = 64 * 1024
        var cursor = bytes.startIndex
        while cursor < bytes.endIndex {
            let next = min(bytes.index(cursor, offsetBy: chunkSize, limitedBy: bytes.endIndex) ?? bytes.endIndex, bytes.endIndex)
            try bytes[cursor..<next].withUnsafeBytes { buf in
                try sink.write(buf)
            }
            cursor = next
        }
    }
}
