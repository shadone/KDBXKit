//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

extension Attach {
    struct Extract: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "extract",
            abstract: "Extract one attachment from an entry. Writes to stdout by default; refuses to write binary to a TTY."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Argument(help: ArgumentHelp("Attachment key (filename inside the entry).", valueName: "name"))
        var attachmentName: String

        @Option(
            name: [.customShort("o"), .customLong("output")],
            help: ArgumentHelp("Write extracted bytes to this path instead of stdout.", valueName: "path")
        )
        var outputPath: String?

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)

            guard let binary = entry.binaries.first(where: { $0.key == attachmentName }) else {
                throw AttachError.notFound(attachmentName)
            }

            let bytes: Data
            switch binary.value {
            case let .inline(data, _):
                bytes = data
            case let .ref(idx):
                guard Int(idx) < content.innerHeader.binaryContent.count else {
                    throw AttachError.corruptRef(attachmentName, idx)
                }
                bytes = content.innerHeader.binaryContent[Int(idx)].data
            }

            if let outputPath {
                try bytes.write(to: URL(filePath: outputPath))
            } else {
                if isatty(STDOUT_FILENO) != 0 {
                    throw AttachError.refuseTTY
                }
                FileHandle.standardOutput.write(bytes)
            }
        }
    }
}

enum AttachError: Error, CustomStringConvertible {
    case notFound(String)
    case corruptRef(String, UInt32)
    case refuseTTY

    var description: String {
        switch self {
        case let .notFound(name):
            return "No attachment named `\(name)` on this entry."
        case let .corruptRef(name, idx):
            return "Attachment `\(name)` references inner-header binary #\(idx), which is out of range. Vault may be corrupt."
        case .refuseTTY:
            return "Refusing to write binary data to a TTY. Redirect to a file or pipe, or pass --output <path>."
        }
    }
}
