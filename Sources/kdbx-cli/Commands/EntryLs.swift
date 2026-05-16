//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension Entry {
    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "ls",
            abstract: "List entries in the vault. Filter by group subtree or substring match on fields."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @OptionGroup()
        var secretsOptions: SecretsOptions

        @Option(
            name: .customLong("in"),
            help: ArgumentHelp(
                "Restrict listing to entries within this group (and its descendants). UUID or path.",
                valueName: "uuid-or-path"
            )
        )
        var inGroup: String?

        @Option(
            name: .customLong("filter"),
            parsing: .singleValue,
            help: ArgumentHelp(
                "Filter entries where <field>'s value contains <substring> (case-insensitive). Repeatable; multiple filters AND together. Field is matched against the entry's KDBX string keys (e.g. `Title`, `URL`, `UserName`, `Notes`, or a custom field name).",
                valueName: "field=substring"
            )
        )
        var filters: [String] = []

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let startingGroup = try resolveStartingGroup(in: content.database)
            let predicates = try filters.map(EntryFilterPredicate.parse)

            let snapshot = EntryListSnapshot(
                rootGroup: startingGroup,
                innerHeader: content.innerHeader,
                predicates: predicates,
                showSecrets: secretsOptions.showSecrets
            )

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }
        }

        private func resolveStartingGroup(in db: KDBX) throws -> KDBX.Group {
            guard let raw = inGroup else { return db.root.group }
            let resolved: ResolvedAddress
            if let id = UUID(uuidString: raw) {
                resolved = .uuid(id)
            } else {
                resolved = .path(PathComponents(raw: raw))
            }
            return try AddressResolver.findGroup(resolved, in: db)
        }
    }
}

/// Parsed `<field>=<substring>` filter.
struct EntryFilterPredicate {
    let field: String
    let needle: String

    static func parse(_ raw: String) throws -> EntryFilterPredicate {
        guard let eq = raw.firstIndex(of: "=") else {
            throw EntryFilterError.malformed(raw)
        }
        let field = String(raw[..<eq])
        let needle = String(raw[raw.index(after: eq)...])
        if field.isEmpty {
            throw EntryFilterError.malformed(raw)
        }
        return EntryFilterPredicate(field: field, needle: needle.lowercased())
    }

    func matches(_ entry: KDBX.Entry) -> Bool {
        for kv in entry.strings where kv.key == field {
            return kv.value.revealedString.lowercased().contains(needle)
        }
        return false
    }
}

enum EntryFilterError: Error, CustomStringConvertible {
    case malformed(String)

    var description: String {
        switch self {
        case let .malformed(raw):
            return "Bad --filter value `\(raw)`. Expected <field>=<substring> with a non-empty field."
        }
    }
}
