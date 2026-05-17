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
/// - `.file(URL)`: the encrypted bytes stay on disk. Re-streaming
///   reads bytes via `NSFileCoordinator` to interoperate with iCloud
///   Drive writes. The URL must remain accessible for the lifetime
///   of any `LazyKDBXContent` derived from it; security-scoped
///   bookmark callers are responsible for keeping access open.
public enum KDBXSource: Sendable {
    case data(Data)
    case file(URL)

    /// Read the entire encrypted payload into a `Data` buffer. Used
    /// by the open / re-stream paths; freshly created on every call
    /// so the caller can release it as soon as decryption is done.
    /// For `.file`, this is the only step that materializes the
    /// encrypted bytes in process memory — peak memory during decrypt
    /// is ~file_size; idle memory is metadata only.
    public func readAll() throws -> Data {
        switch self {
        case let .data(data):
            return data
        case let .file(url):
            var coordinatorError: NSError?
            var readResult: Result<Data, Swift.Error> = .failure(KDBXSourceError.readFailed)
            NSFileCoordinator().coordinate(
                readingItemAt: url,
                options: [.withoutChanges],
                error: &coordinatorError
            ) { coordinatedURL in
                do {
                    readResult = .success(try Data(contentsOf: coordinatedURL))
                } catch {
                    readResult = .failure(error)
                }
            }
            if let coordinatorError {
                throw coordinatorError
            }
            return try readResult.get()
        }
    }
}

public enum KDBXSourceError: Swift.Error, Sendable {
    case readFailed
}
