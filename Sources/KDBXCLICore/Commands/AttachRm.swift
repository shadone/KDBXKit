//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Attach {
    struct Rm: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rm",
            abstract: "Remove an attachment from an entry. Optionally garbage-collects unreferenced inner-header binaries."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var backupOptions: BackupOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        @Argument(help: ArgumentHelp("Attachment key to remove.", valueName: "name"))
        var attachmentName: String

        @Flag(
            name: .customLong("gc"),
            help: "After removing the ref, drop any inner-header binary no longer referenced by any entry. Rewrites remaining ref indices."
        )
        var gc: Bool = false

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)

            guard entry.binaries.contains(where: { $0.key == attachmentName }) else {
                throw AttachError.notFound(attachmentName)
            }

            let now = Date()
            var updated = content
            let mutated = TreeMutator.mutateEntry(uuid: entry.uuid, in: &updated.database) { e in
                e.binaries.removeAll { $0.key == attachmentName }
                TreeMutator.bumpModified(&e.times, now: now)
            }
            guard mutated else {
                throw AttachRmError.entryVanished(entry.uuid)
            }

            var gcStats: (kept: Int, dropped: Int)?
            if gc {
                gcStats = garbageCollectBinaries(in: &updated)
            }

            try VaultWriting.writeAtomically(
                content: updated,
                unlockData: unlock,
                to: URL(filePath: commonOptions.filepath),
                backup: backupOptions.backup
            )

            if let gcStats {
                print("Removed attachment `\(attachmentName)` from entry \(entry.uuid.uuidString). GC: dropped \(gcStats.dropped), kept \(gcStats.kept).")
            } else {
                print("Removed attachment `\(attachmentName)` from entry \(entry.uuid.uuidString).")
            }
        }

        /// Walk every entry in the tree, collect the set of referenced
        /// inner-header binary indices, drop the rest, and renumber the refs
        /// on the surviving binaries so they keep pointing at the same
        /// bytes. (Inline binaries are independent of the inner header and
        /// don't need rewriting.)
        private func garbageCollectBinaries(in content: inout KDBXContent) -> (kept: Int, dropped: Int) {
            var referenced: Set<UInt32> = []
            content.database.visitEntries(in: content.database.root.group) { entry in
                for b in entry.binaries {
                    if case let .ref(idx) = b.value {
                        referenced.insert(idx)
                    }
                }
                for hist in entry.history {
                    for b in hist.binaries {
                        if case let .ref(idx) = b.value {
                            referenced.insert(idx)
                        }
                    }
                }
            }

            let oldCount = content.innerHeader.binaryContent.count
            if referenced.count == oldCount {
                return (kept: oldCount, dropped: 0)
            }

            // Build the survivor list and an old→new index remap.
            var survivors: [InnerHeader.BinaryContent] = []
            var remap: [UInt32: UInt32] = [:]
            for oldIdx in 0..<UInt32(oldCount) {
                if referenced.contains(oldIdx) {
                    remap[oldIdx] = UInt32(survivors.count)
                    survivors.append(content.innerHeader.binaryContent[Int(oldIdx)])
                }
            }
            content.innerHeader.binaryContent = survivors

            // Rewrite refs across the whole tree (current + history).
            rewriteRefs(in: &content.database.root.group, remap: remap)

            return (kept: survivors.count, dropped: oldCount - survivors.count)
        }

        private func rewriteRefs(in group: inout KDBX.Group, remap: [UInt32: UInt32]) {
            for i in group.entries.indices {
                rewriteRefs(in: &group.entries[i], remap: remap)
            }
            for i in group.groups.indices {
                rewriteRefs(in: &group.groups[i], remap: remap)
            }
        }

        private func rewriteRefs(in entry: inout KDBX.Entry, remap: [UInt32: UInt32]) {
            for i in entry.binaries.indices {
                if case let .ref(idx) = entry.binaries[i].value, let newIdx = remap[idx] {
                    let key = entry.binaries[i].key
                    entry.binaries[i] = KDBX.ProtectedBinary(key: key, value: .ref(newIdx))
                }
            }
            for i in entry.history.indices {
                rewriteRefs(in: &entry.history[i], remap: remap)
            }
        }
    }
}

enum AttachRmError: Error, CustomStringConvertible {
    case entryVanished(UUID)

    var description: String {
        switch self {
        case let .entryVanished(uuid):
            return "Entry \(uuid.uuidString) disappeared between lookup and write (concurrent edit?)."
        }
    }
}
