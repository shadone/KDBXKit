//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Attach {
    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List attachments on a single entry."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)

            let snapshot = AttachmentListSnapshot(
                entry: entry,
                innerHeader: content.innerHeader
            )

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }
    }
}

struct AttachmentListSnapshot: Encodable {
    let entryUUID: String
    let attachments: [Attachment]

    struct Attachment: Encodable {
        let key: String
        let source: BinarySnapshot.Source
        let size: Int
        let ref: UInt32?
        let protectedOnDisk: Bool
        /// Mirrors ``BinarySnapshot/dangling`` — the ref points outside
        /// the binary pool of a corrupt-but-parseable vault.
        let dangling: Bool
    }

    init(entry: KDBX.Entry, innerHeader: InnerHeader) {
        entryUUID = entry.uuid.uuidString
        attachments = entry.binaries.map { binary in
            switch binary.value {
            case let .inline(data, protected):
                return Attachment(
                    key: binary.key,
                    source: .inline,
                    size: data.count,
                    ref: nil,
                    protectedOnDisk: protected,
                    dangling: false
                )
            case let .ref(idx):
                guard Int(idx) < innerHeader.binaryContent.count else {
                    return Attachment(
                        key: binary.key,
                        source: .ref,
                        size: 0,
                        ref: idx,
                        protectedOnDisk: false,
                        dangling: true
                    )
                }
                let element = innerHeader.binaryContent[Int(idx)]
                return Attachment(
                    key: binary.key,
                    source: .ref,
                    size: element.data.count,
                    ref: idx,
                    protectedOnDisk: element.shouldBeProtected,
                    dangling: false
                )
            }
        }
    }

    func printHuman() {
        if attachments.isEmpty {
            print("(no attachments)")
            return
        }
        for a in attachments {
            let prot = a.protectedOnDisk ? " [protected]" : ""
            switch a.source {
            case .inline:
                print("\(a.key): \(a.size) bytes (inline)\(prot)")
            case .ref where a.dangling:
                print("\(a.key): DANGLING (ref=\(a.ref ?? 0) has no pool entry)")
            case .ref:
                print("\(a.key): \(a.size) bytes (ref=\(a.ref ?? 0))\(prot)")
            }
        }
    }
}
