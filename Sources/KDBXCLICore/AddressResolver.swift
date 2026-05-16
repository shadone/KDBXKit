//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

/// User-facing way to specify an entry or group on the command line. Accepts:
///   - A UUID (`174F2960-9627-FC93-984A-3C8961864DA5`).
///   - A path (`/Banking/Chase`, `Banking/Chase`). The leading slash is
///     optional; the root group is always the implicit starting point.
/// `--uuid` / `--path` flags disambiguate when a value happens to look like
/// the other form (rare but possible if a title is a UUID-shaped string).
struct AddressOptions: ParsableArguments {
    @Argument(help: ArgumentHelp("UUID or `/`-separated path to the target.", valueName: "uuid-or-path"))
    var address: String?

    @Option(name: .customLong("uuid"), help: ArgumentHelp("Interpret as a UUID. Skips auto-detection.", valueName: "uuid"))
    var explicitUUID: String?

    @Option(name: .customLong("path"), help: ArgumentHelp("Interpret as a `/`-separated path.", valueName: "path"))
    var explicitPath: String?

    func resolved() throws -> ResolvedAddress {
        if let raw = explicitUUID {
            guard let id = UUID(uuidString: raw) else {
                throw AddressError.invalidUUID(raw)
            }
            return .uuid(id)
        }
        if let raw = explicitPath {
            return .path(PathComponents(raw: raw))
        }
        guard let raw = address else {
            throw AddressError.missing
        }
        if let id = UUID(uuidString: raw) {
            return .uuid(id)
        }
        return .path(PathComponents(raw: raw))
    }
}

enum ResolvedAddress {
    case uuid(UUID)
    case path(PathComponents)
}

/// Path split into ordered name segments. Leading and trailing empty segments
/// from "/" are dropped, so "/A/B", "A/B", and "A/B/" all parse identically.
struct PathComponents {
    let segments: [String]
    let raw: String

    init(raw: String) {
        self.raw = raw
        segments = raw.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    }

    var isRoot: Bool { segments.isEmpty }
}

enum AddressError: Error, CustomStringConvertible {
    case missing
    case invalidUUID(String)
    case entryNotFound(String)
    case groupNotFound(String)
    case ambiguous(String, matches: [UUID])

    var description: String {
        switch self {
        case .missing:
            return "Missing address. Provide a UUID, a path, or pass --uuid / --path."
        case let .invalidUUID(raw):
            return "Not a valid UUID: \(raw)"
        case let .entryNotFound(addr):
            return "No entry matched \(addr)."
        case let .groupNotFound(addr):
            return "No group matched \(addr)."
        case let .ambiguous(addr, matches):
            let ids = matches.map(\.uuidString).joined(separator: "\n  ")
            return "Path \(addr) is ambiguous. Use --uuid to pick one:\n  \(ids)"
        }
    }
}

enum AddressResolver {
    // MARK: - Entries

    static func findEntry(_ address: ResolvedAddress, in db: KDBX) throws -> KDBX.Entry {
        switch address {
        case let .uuid(id):
            guard let entry = entry(withUUID: id, in: db.root.group) else {
                throw AddressError.entryNotFound(id.uuidString)
            }
            return entry
        case let .path(path):
            let matches = entries(matchingPath: path.segments, in: db.root.group)
            switch matches.count {
            case 0:
                throw AddressError.entryNotFound("/\(path.segments.joined(separator: "/"))")
            case 1:
                return matches[0]
            default:
                throw AddressError.ambiguous(
                    "/\(path.segments.joined(separator: "/"))",
                    matches: matches.map(\.uuid)
                )
            }
        }
    }

    // MARK: - Groups

    /// Resolves a group address. `nil` returns the root group (used by
    /// commands where the group argument is optional, e.g. `group ls`).
    static func findGroup(_ address: ResolvedAddress?, in db: KDBX) throws -> KDBX.Group {
        guard let address else {
            return db.root.group
        }
        switch address {
        case let .uuid(id):
            guard let group = group(withUUID: id, in: db.root.group) else {
                throw AddressError.groupNotFound(id.uuidString)
            }
            return group
        case let .path(path):
            if path.isRoot {
                return db.root.group
            }
            let matches = groups(matchingPath: path.segments, in: db.root.group)
            switch matches.count {
            case 0:
                throw AddressError.groupNotFound("/\(path.segments.joined(separator: "/"))")
            case 1:
                return matches[0]
            default:
                throw AddressError.ambiguous(
                    "/\(path.segments.joined(separator: "/"))",
                    matches: matches.map(\.uuid)
                )
            }
        }
    }

    // MARK: - Traversal primitives

    private static func entry(withUUID id: UUID, in group: KDBX.Group) -> KDBX.Entry? {
        for entry in group.entries where entry.uuid == id {
            return entry
        }
        for child in group.groups {
            if let found = entry(withUUID: id, in: child) {
                return found
            }
        }
        return nil
    }

    private static func group(withUUID id: UUID, in group: KDBX.Group) -> KDBX.Group? {
        if group.uuid == id { return group }
        for child in group.groups {
            if let found = self.group(withUUID: id, in: child) {
                return found
            }
        }
        return nil
    }

    private static func entries(matchingPath segments: [String], in root: KDBX.Group) -> [KDBX.Entry] {
        // The last segment is the entry Title; everything before it identifies
        // the parent group chain.
        guard let targetTitle = segments.last else { return [] }
        let groupSegments = Array(segments.dropLast())
        let parents = groups(matchingPath: groupSegments, in: root, allowRoot: true)
        var hits: [KDBX.Entry] = []
        for parent in parents {
            for entry in parent.entries where entryTitle(of: entry) == targetTitle {
                hits.append(entry)
            }
        }
        return hits
    }

    private static func groups(
        matchingPath segments: [String],
        in root: KDBX.Group,
        allowRoot: Bool = false
    ) -> [KDBX.Group] {
        // Empty path → only the root (when allowed). Used by entry path
        // resolution to allow `/Title` for entries directly in root.
        if segments.isEmpty {
            return allowRoot ? [root] : []
        }
        return descend(into: root, remaining: segments[...])
    }

    private static func descend(into group: KDBX.Group, remaining: ArraySlice<String>) -> [KDBX.Group] {
        guard let head = remaining.first else { return [group] }
        let rest = remaining.dropFirst()
        var hits: [KDBX.Group] = []
        for child in group.groups where (child.name ?? "") == head {
            hits.append(contentsOf: descend(into: child, remaining: rest))
        }
        return hits
    }

    /// Look up an entry's effective Title (the value of its "Title" string).
    /// KDBX entries can technically lack a Title field; treat that as "".
    private static func entryTitle(of entry: KDBX.Entry) -> String {
        for s in entry.strings where s.key == "Title" {
            return s.value.revealedString
        }
        return ""
    }
}
