//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Group {
    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List immediate child groups of a group (default: root)."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @Argument(help: ArgumentHelp("Parent group address (UUID or path). Defaults to root.", valueName: "uuid-or-path"))
        var parent: String?

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let parentGroup = try resolveParent(in: content.database)
            let snapshot = GroupListSnapshot(parent: parentGroup)

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }

        private func resolveParent(in db: KDBX) throws -> KDBX.Group {
            guard let raw = parent else { return db.root.group }
            let resolved: ResolvedAddress = UUID(uuidString: raw)
                .map(ResolvedAddress.uuid) ?? .path(PathComponents(raw: raw))
            return try AddressResolver.findGroup(resolved, in: db)
        }
    }
}

struct GroupListSnapshot: Encodable {
    let parentUUID: String
    let parentName: String
    let children: [ChildSnapshot]

    struct ChildSnapshot: Encodable {
        let uuid: String
        let name: String
        let entryCount: Int
        let subgroupCount: Int
    }

    init(parent: KDBX.Group) {
        parentUUID = parent.uuid.uuidString
        parentName = parent.name ?? ""
        children = parent.groups.map { g in
            ChildSnapshot(
                uuid: g.uuid.uuidString,
                name: g.name ?? "",
                entryCount: g.entries.count,
                subgroupCount: g.groups.count
            )
        }
    }

    func printHuman() {
        if children.isEmpty {
            print("(no subgroups)")
            return
        }
        for child in children {
            print("\(child.name) (uuid=\(child.uuid), entries=\(child.entryCount), subgroups=\(child.subgroupCount))")
        }
    }
}
