//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Where a KDBX file's encrypted bytes live. Lazy reads call back
/// into this to re-read the file on demand without holding a
/// process-memory copy.
///
/// - `.data(Data)`: the file was loaded into memory at open time
///   (e.g. tests, in-process buffers). Re-streaming is O(file_size)
///   but reads from RAM, not disk.
/// - `.file(URL)`: the encrypted bytes stay on disk. On Apple
///   platforms re-streaming reads bytes via `NSFileCoordinator` to
///   interoperate with iCloud Drive writes; on Linux the file is
///   opened directly. The URL must remain accessible for the lifetime
///   of any `LazyKDBXContent` derived from it; on Apple,
///   security-scoped bookmark callers are responsible for keeping
///   access open.
public enum KDBXSource: Sendable {
    case data(Data)
    case file(URL)

    /// Read the entire encrypted payload into a `Data` buffer. Used
    /// by the open / re-stream paths; freshly created on every call
    /// so the caller can release it as soon as decryption is done.
    /// For `.file`, this is the only step that materializes the
    /// encrypted bytes in process memory — peak memory during decrypt
    /// is ~file_size; idle memory is metadata only.
    ///
    /// Pass `mappedIfSafe: true` to memory-map the file instead of copying
    /// it into anonymous memory. Mapped, clean file pages are excluded from
    /// the Darwin `phys_footprint` (the metric iOS jetsam enforces), so the
    /// encrypted bytes stop counting against a memory-capped host's budget —
    /// the streaming open relies on this for size-independence (peak stays
    /// at the KDF + working set, not the file size). Default `false` keeps
    /// the eager / re-stream paths copying as before.
    public func readAll(mappedIfSafe: Bool = false) throws -> Data {
        switch self {
        case let .data(data):
            return data
        case let .file(url):
            return try Self.readFile(at: url, mappedIfSafe: mappedIfSafe)
        }
    }

    #if canImport(Darwin)
    private static func readFile(at url: URL, mappedIfSafe: Bool) throws -> Data {
        let options: Data.ReadingOptions = mappedIfSafe ? [.mappedIfSafe] : []
        var coordinatorError: NSError?
        var readResult: Result<Data, Swift.Error> = .failure(KDBXSourceError.readFailed)
        NSFileCoordinator().coordinate(
            readingItemAt: url,
            options: [.withoutChanges],
            error: &coordinatorError
        ) { coordinatedURL in
            do {
                readResult = .success(try Data(contentsOf: coordinatedURL, options: options))
            } catch {
                readResult = .failure(error)
            }
        }
        if let coordinatorError {
            throw coordinatorError
        }
        return try readResult.get()
    }
    #else
    private static func readFile(at url: URL, mappedIfSafe: Bool) throws -> Data {
        try Data(contentsOf: url, options: mappedIfSafe ? [.mappedIfSafe] : [])
    }
    #endif
}

public enum KDBXSourceError: Swift.Error, Sendable {
    case readFailed
}
