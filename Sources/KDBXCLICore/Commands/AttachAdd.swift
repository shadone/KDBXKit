//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Attach {
    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Attach a file (or stdin) to an entry. KDBX v4: bytes go into the inner header and the entry holds a ref."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Option(
            name: [.customShort("f"), .customLong("file")],
            help: ArgumentHelp("Path to the file to attach. Use `-` (or omit) to read bytes from stdin.", valueName: "path")
        )
        var filePath: String?

        @Option(
            name: .customLong("name"),
            help: ArgumentHelp(
                "Override the attachment key. Defaults to the file's basename (or `attachment` when reading stdin).",
                valueName: "name"
            )
        )
        var attachmentName: String?

        @Flag(
            name: .customLong("protected"),
            help: "Mark the inner-header binary as `shouldBeProtected` (process-memory hint for clients). Off by default."
        )
        var protected: Bool = false

        @Flag(
            name: .customLong("force"),
            help: "Overwrite an existing attachment with the same key on this entry."
        )
        var force: Bool = false

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)

            let (data, defaultName) = try loadAttachmentBytes()
            let key = attachmentName ?? defaultName

            if entry.binaries.contains(where: { $0.key == key }), !force {
                throw AttachAddError.keyExists(key)
            }

            var updated = content

            // Reuse the inner-header binary if some entry already references
            // a byte-identical blob with matching protection — avoids growing
            // the file when the same attachment is added to multiple entries.
            let refIndex: UInt32
            if let existingIdx = updated.innerHeader.binaryContent.firstIndex(where: {
                $0.data == data && $0.shouldBeProtected == protected
            }) {
                refIndex = UInt32(existingIdx)
            } else {
                updated.innerHeader.binaryContent.append(
                    InnerHeader.BinaryContent(shouldBeProtected: protected, data: data)
                )
                refIndex = UInt32(updated.innerHeader.binaryContent.count - 1)
            }

            let now = Date()
            let mutated = TreeMutator.mutateEntry(uuid: entry.uuid, in: &updated.database) { e in
                if force, let existingIdx = e.binaries.firstIndex(where: { $0.key == key }) {
                    e.binaries.remove(at: existingIdx)
                }
                e.binaries.append(KDBX.ProtectedBinary(key: key, value: .ref(refIndex)))
                TreeMutator.bumpModified(&e.times, now: now)
            }
            guard mutated else {
                throw AttachAddError.entryVanished(entry.uuid)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            print("Attached \(key) (\(data.count) bytes, ref=\(refIndex)) to entry \(entry.uuid.uuidString).")
        }

        /// Returns the bytes and a sensible default key. Defaults:
        ///   - file path `foo/bar.png` → "bar.png"
        ///   - stdin → "attachment"
        private func loadAttachmentBytes() throws -> (Data, String) {
            if let filePath, filePath != "-" {
                let url = URL(filePath: filePath)
                let data: Data
                do {
                    data = try Data(contentsOf: url)
                } catch {
                    throw AttachAddError.cannotRead(filePath, underlying: error)
                }
                return (data, url.lastPathComponent)
            }
            let data = FileHandle.standardInput.readDataToEndOfFile()
            return (data, "attachment")
        }
    }
}

enum AttachAddError: Error, CustomStringConvertible {
    case cannotRead(String, underlying: Error)
    case keyExists(String)
    case entryVanished(UUID)

    var description: String {
        switch self {
        case let .cannotRead(path, error):
            return "Cannot read attachment file at \(path): \(error.localizedDescription)"
        case let .keyExists(key):
            return "An attachment named `\(key)` already exists on this entry. Pass --force to overwrite."
        case let .entryVanished(uuid):
            return "Entry \(uuid.uuidString) disappeared between lookup and write (concurrent edit?)."
        }
    }
}
