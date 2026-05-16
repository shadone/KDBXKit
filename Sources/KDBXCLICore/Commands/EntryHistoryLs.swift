//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry.History {
    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List prior versions of an entry, oldest → newest."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @OptionGroup()
        var addressOptions: AddressOptions

        mutating func run() throws {
            let unlock = try commonOptions.credentials.resolveRequired()
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlock)
            else {
                throw AppError.wrongCredentials
            }

            let address = try addressOptions.resolved()
            let entry = try AddressResolver.findEntry(address, in: content.database)

            let snapshot = EntryHistoryListSnapshot(entry: entry)
            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }
    }
}

struct EntryHistoryListSnapshot: Encodable {
    let entryUUID: String
    let entries: [Item]

    struct Item: Encodable {
        let index: Int
        let title: String
        let modified: Date?
    }

    init(entry: KDBX.Entry) {
        entryUUID = entry.uuid.uuidString
        entries = entry.history.enumerated().map { idx, snap in
            Item(
                index: idx,
                title: snap.strings.first(where: { $0.key == EntryField.title })?.value.revealedString ?? "",
                modified: snap.times?.lastModificationTime
            )
        }
    }

    func printHuman() {
        if entries.isEmpty {
            print("(no prior versions)")
            return
        }
        let formatter = ISO8601DateFormatter()
        for item in entries {
            let modString = item.modified.map { formatter.string(from: $0) } ?? "(unknown)"
            print("[\(item.index)] modified \(modString): \(item.title)")
        }
    }
}
