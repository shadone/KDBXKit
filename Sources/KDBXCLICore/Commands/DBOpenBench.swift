//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    /// Open a vault and exit — a measurement harness for parse memory.
    ///
    /// Wrap with `/usr/bin/time -l` to capture peak footprint:
    /// `printf '%s' PW | kdbx db open-bench vault.kdbx --password-stdin`
    /// versus `--lazy`. Reproduces the iOS AutoFill parse footprint on
    /// macOS without the device.
    struct OpenBench: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "open-bench",
            abstract: "Open a vault (eager or --lazy metadata-only) and exit — for measuring parse memory under `/usr/bin/time -l`."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @Flag(name: .long, help: "Use the lazy metadata-only parse (binaries stay on disk) instead of the eager parse.")
        var lazy = false

        @Flag(name: .long, help: "Use the fully streaming metadata-only parse (binaries discarded as they decompress).")
        var streaming = false

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolveRequired()
            if streaming {
                let content = try KDBXReader.openMetadataStreaming(
                    from: .file(URL(filePath: commonOptions.filepath)),
                    unlockData: unlockData
                )
                print("streaming open OK — \(content.binaries.count) binary record(s), metadata only")
            } else if lazy {
                let content = try KDBXReader.openMetadataOnly(
                    from: .file(URL(filePath: commonOptions.filepath)),
                    unlockData: unlockData
                )
                print("lazy open OK — \(content.binaries.count) binary record(s), metadata only")
            } else {
                guard
                    case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
                else {
                    throw AppError.wrongCredentials
                }
                print("eager open OK — \(content.innerHeader.binaryContent.count) binary record(s) resident")
            }
        }
    }
}
