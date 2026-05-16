//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

/// Serialize a `KDBXContent` to KDBX bytes in memory, then atomically write
/// to disk. Shared by every mutating command in P3+.
enum VaultWriting {
    static func writeAtomically(
        content: KDBXContent,
        unlockData: UnlockData,
        to url: URL,
        backup: Bool,
        regenerateSalts: Bool = true
    ) throws {
        let stream = OutputStream(toMemory: ())
        stream.open()
        let writer = KDBXWriter(to: stream)
        try writer.write(content, unlockData: unlockData, regenerateSalts: regenerateSalts)
        guard let data = stream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw VaultWritingError.streamReturnedNoData
        }
        try AtomicFileWriter.write(data, to: url, backup: backup)
    }
}

enum VaultWritingError: Error, CustomStringConvertible {
    case streamReturnedNoData

    var description: String {
        switch self {
        case .streamReturnedNoData:
            return "Memory output stream did not yield Data after KDBXWriter finished."
        }
    }
}

/// `--backup` flag shared by every mutating command. Threaded through to
/// `AtomicFileWriter.write(backup:)`.
struct BackupOptions: ParsableArguments {
    @Flag(
        name: .customLong("backup"),
        help: "Before writing, copy the existing file to <file>.kdbx.bak. Replaces any prior .bak."
    )
    var backup: Bool = false
}
