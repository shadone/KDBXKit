//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Streaming consumer of decrypted binary bytes. The lazy KDBX reader
/// writes chunks as it decompresses, so the caller controls what
/// happens to the bytes — accumulate into `Data`, into a
/// page-locked `SecureBytes`, or stream directly to a file URL.
///
/// `finalize()` runs once after the last `write(_:)` so sinks that
/// need to flush (e.g. `URLSink` closing its file handle) can do so
/// without the caller juggling lifetime.
public protocol ByteSink {
    /// Consume `chunk` — append to a buffer, write to a file
    /// handle, etc. Called zero or more times per stream, never
    /// after ``finalize()``.
    mutating func write(_ chunk: UnsafeRawBufferPointer) throws

    /// Called once after the last ``write(_:)``. Sinks that need to
    /// flush state (close file handles, materialize the result) do
    /// it here. Subsequent ``write(_:)`` calls are not permitted.
    mutating func finalize() throws
}

public extension ByteSink {
    mutating func write(_ data: Data) throws {
        try data.withUnsafeBytes { buf in
            try write(buf)
        }
    }
}

/// Default sink for unprotected binaries — accumulates into a `Data`
/// buffer. Caller reads ``data`` after ``finalize()``.
public struct DataSink: ByteSink {
    /// Accumulated bytes. Safe to read after ``finalize()``; reading
    /// mid-stream is permitted but the buffer is still growing.
    public private(set) var data: Data

    /// - Parameter capacityHint: pre-allocates the underlying `Data`
    ///   to avoid copies on each grow. Use the known
    ///   ``BinaryMetadata/sizeBytes`` for a tight fit.
    public init(capacityHint: Int = 0) {
        data = Data(capacity: capacityHint)
    }

    public mutating func write(_ chunk: UnsafeRawBufferPointer) throws {
        guard let base = chunk.baseAddress, !chunk.isEmpty else { return }
        data.append(base.assumingMemoryBound(to: UInt8.self), count: chunk.count)
    }

    public mutating func finalize() throws { }
}

/// Sink for protected binaries. The bytes are mlocked + zero-on-deinit
/// only once `takeSecureBytes()` wraps them; DURING accumulation they
/// live in an ordinary heap buffer that is zeroed on take (and on
/// explicit growth), but not if the sink is dropped mid-stream after a
/// throw. Pass an exact `capacityHint` (``BinaryMetadata/sizeBytes``)
/// so growth never reallocates. Callers should consume the result via a
/// `withRevealedBytes` scope and let the value go out of scope ASAP.
public struct SecureBytesSink: ByteSink {
    private var buffer: [UInt8]

    /// - Parameter capacityHint: reserves the underlying storage to
    ///   avoid copies during accumulation. Use the known
    ///   ``BinaryMetadata/sizeBytes`` for a tight fit.
    public init(capacityHint: Int = 0) {
        buffer = []
        buffer.reserveCapacity(capacityHint)
    }

    public mutating func write(_ chunk: UnsafeRawBufferPointer) throws {
        guard let base = chunk.baseAddress, !chunk.isEmpty else { return }
        // Growth is handled explicitly: Array's own reallocation frees
        // the old storage without zeroing, leaving a ghost copy of the
        // secret on the heap. Copy into the larger buffer first, then
        // zero the outgrown one before releasing it.
        if buffer.capacity < buffer.count + chunk.count {
            var bigger: [UInt8] = []
            bigger.reserveCapacity(max(buffer.capacity * 2, buffer.count + chunk.count))
            bigger.append(contentsOf: buffer)
            buffer.withUnsafeMutableBufferPointer { ptr in
                guard let oldBase = ptr.baseAddress else { return }
                oldBase.initialize(repeating: 0, count: ptr.count)
            }
            buffer = bigger
        }
        let typed = UnsafeBufferPointer(
            start: base.assumingMemoryBound(to: UInt8.self),
            count: chunk.count
        )
        buffer.append(contentsOf: typed)
    }

    public mutating func finalize() throws { }

    /// Take the buffered bytes as `SecureBytes` and zero the local
    /// holding buffer. The returned `SecureBytes` is the only handle
    /// to the data — the caller is responsible for using it inside a
    /// scoped accessor and dropping it promptly.
    public mutating func takeSecureBytes() -> SecureBytes {
        let bytes = SecureBytes(buffer)
        buffer.withUnsafeMutableBufferPointer { ptr in
            guard let base = ptr.baseAddress else { return }
            base.initialize(repeating: 0, count: ptr.count)
        }
        buffer.removeAll(keepingCapacity: false)
        return bytes
    }
}

/// Sink that streams bytes straight to a file URL — used by the
/// "export attachment" path so bytes never sit in `Data` in our
/// process memory. The file is created (or truncated) at init and
/// closed at `finalize`.
public struct URLSink: ByteSink {
    private let handle: FileHandle

    /// Destination URL the sink is writing to.
    public let url: URL

    /// Create / truncate the file at `url` and open it for writing.
    /// The file handle is closed when ``finalize()`` runs.
    public init(writingTo url: URL) throws {
        self.url = url
        // Touch the file to ensure it exists and is empty.
        try Data().write(to: url, options: .atomic)
        handle = try FileHandle(forWritingTo: url)
    }

    public mutating func write(_ chunk: UnsafeRawBufferPointer) throws {
        guard let base = chunk.baseAddress, !chunk.isEmpty else { return }
        // FileHandle.write(contentsOf:) copies into a Data internally;
        // unavoidable for the framework boundary. The Data is
        // short-lived (this scope).
        let bytes = Data(bytes: base, count: chunk.count)
        try handle.write(contentsOf: bytes)
    }

    public mutating func finalize() throws {
        try handle.close()
    }
}
