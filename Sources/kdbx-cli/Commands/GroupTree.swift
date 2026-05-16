//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Group {
    struct Tree: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "tree",
            abstract: "Print the group hierarchy as an ASCII tree."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @Flag(name: .customLong("entries"), help: "Also include entries under each group.")
        var includeEntries: Bool = false

        @Argument(help: ArgumentHelp("Root of the tree (UUID or path). Defaults to vault root.", valueName: "uuid-or-path"))
        var root: String?

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let rootGroup = try resolveRoot(in: content.database)
            let snapshot = GroupTreeSnapshot(root: rootGroup, includeEntries: includeEntries)

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }

        private func resolveRoot(in db: KDBX) throws -> KDBX.Group {
            guard let raw = root else { return db.root.group }
            let resolved: ResolvedAddress = UUID(uuidString: raw)
                .map(ResolvedAddress.uuid) ?? .path(PathComponents(raw: raw))
            return try AddressResolver.findGroup(resolved, in: db)
        }
    }
}

struct GroupTreeSnapshot: Encodable {
    let root: Node
    let includeEntries: Bool

    struct Node: Encodable {
        let uuid: String
        let name: String
        let entries: [EntryStub]?
        let groups: [Node]
    }

    struct EntryStub: Encodable {
        let uuid: String
        let title: String
    }

    init(root: KDBX.Group, includeEntries: Bool) {
        self.includeEntries = includeEntries
        self.root = Self.buildNode(root, includeEntries: includeEntries)
    }

    private static func buildNode(_ g: KDBX.Group, includeEntries: Bool) -> Node {
        let entries: [EntryStub]? = includeEntries
            ? g.entries.map { EntryStub(uuid: $0.uuid.uuidString, title: titleOf($0)) }
            : nil
        let groups = g.groups.map { buildNode($0, includeEntries: includeEntries) }
        return Node(uuid: g.uuid.uuidString, name: g.name ?? "", entries: entries, groups: groups)
    }

    private static func titleOf(_ entry: KDBX.Entry) -> String {
        for s in entry.strings where s.key == "Title" {
            return s.value.revealedString
        }
        return ""
    }

    func printHuman() {
        print(root.name.isEmpty ? "/" : root.name)
        printChildren(of: root, prefix: "")
    }

    private func printChildren(of node: Node, prefix: String) {
        let entries = node.entries ?? []
        let groups = node.groups
        let totalChildren = entries.count + groups.count

        var index = 0
        for entry in entries {
            let isLast = (index == totalChildren - 1)
            let connector = isLast ? "└── " : "├── "
            print("\(prefix)\(connector)[entry] \(entry.title)")
            index += 1
        }
        for group in groups {
            let isLast = (index == totalChildren - 1)
            let connector = isLast ? "└── " : "├── "
            print("\(prefix)\(connector)\(group.name)")
            let childPrefix = prefix + (isLast ? "    " : "│   ")
            printChildren(of: group, prefix: childPrefix)
            index += 1
        }
    }
}
