//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Writes a `Data` payload to a file with crash-safe semantics: the new
/// content is written to a sibling temp file and then atomically renamed
/// into place. An interrupted write leaves the original file untouched.
///
/// Used by mutating CLI commands (`db rekey`, `entry set`, …) and intended
/// for callers in the iOS/macOS apps that need a "save vault" primitive
/// where the worst case is "old content preserved", never "file truncated".
///
/// `backup: true` saves the existing content to a `.bak` sibling before the
/// rename — useful during heavy edit sessions where re-typing the password
/// to recover is the only alternative. The backup is overwritten on each
/// call, not accumulated, so it doesn't grow unbounded.
public enum AtomicFileWriter {
    public enum WriteError: Error, CustomStringConvertible, Sendable {
        case backupFailed(URL, underlying: Error)
        case writeFailed(URL, underlying: Error)

        public var description: String {
            switch self {
            case let .backupFailed(url, error):
                return "Could not write backup at \(url.path): \(error.localizedDescription)"
            case let .writeFailed(url, error):
                return "Could not write file at \(url.path): \(error.localizedDescription)"
            }
        }
    }

    public static func write(
        _ data: Data,
        to url: URL,
        backup: Bool = false
    ) throws {
        let fm = FileManager.default
        if backup, fm.fileExists(atPath: url.path) {
            let backupURL = url.appendingPathExtension("bak")
            do {
                if fm.fileExists(atPath: backupURL.path) {
                    try fm.removeItem(at: backupURL)
                }
                try fm.copyItem(at: url, to: backupURL)
            } catch {
                throw WriteError.backupFailed(backupURL, underlying: error)
            }
        }
        do {
            // .atomic = write to sibling temp file, fsync, rename(2) into place.
            try data.write(to: url, options: [.atomic])
        } catch {
            throw WriteError.writeFailed(url, underlying: error)
        }
    }
}
