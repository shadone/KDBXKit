//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Per-entry detail view used by `entry show`. Richer than the per-entry
/// shape inside `entry ls` — adds tags, times, and the resolved parent path.
struct EntryDetailSnapshot: Encodable {
    let uuid: String
    let parentPath: String
    let tags: [String]
    let times: TimesDTO?
    let fields: [FieldSnapshot]
    let binaries: [BinarySnapshot]
    let historyCount: Int

    init(
        entry: KDBX.Entry,
        parentPath: [String],
        innerHeader: InnerHeader,
        showSecrets: Bool
    ) {
        uuid = entry.uuid.uuidString
        self.parentPath = "/" + parentPath.joined(separator: "/")
        tags = entry.tags
        times = entry.times.map(TimesDTO.init)
        fields = entry.strings.map { FieldSnapshot($0, showSecrets: showSecrets) }
        binaries = entry.binaries.map { BinarySnapshot(binary: $0, innerHeader: innerHeader) }
        historyCount = entry.history.count
    }

    func printHuman() {
        print("UUID: \(uuid)")
        print("Path: \(parentPath)")
        if !tags.isEmpty {
            print("Tags: \(tags.joined(separator: ", "))")
        }
        if let times {
            times.printHuman(indent: "")
        }
        if historyCount > 0 {
            print("History: \(historyCount) prior version(s)")
        }

        if !fields.isEmpty {
            print("")
            print("Fields:")
            for field in fields {
                print("\t\(field.key)\(field.humanTag): \(field.value)")
            }
        }

        if !binaries.isEmpty {
            print("")
            print("Binaries:")
            for binary in binaries {
                switch binary.source {
                case .inline:
                    print("\t\(binary.key): \(binary.size) bytes")
                case .ref where binary.dangling:
                    print("\t\(binary.key): ref=\(binary.ref ?? 0): DANGLING (no such pool entry)")
                case .ref:
                    print("\t\(binary.key): ref=\(binary.ref ?? 0): \(binary.size) bytes")
                }
            }
        }
    }
}

struct TimesDTO: Encodable {
    let created: Date?
    let modified: Date?
    let accessed: Date?
    let expires: Bool?
    let expiry: Date?
    let usageCount: UInt64?
    let locationChanged: Date?

    init(_ times: KDBX.Times) {
        created = times.creationTime
        modified = times.lastModificationTime
        accessed = times.lastAccessTime
        expires = times.expires
        expiry = times.expiryTime
        usageCount = times.usageCount
        locationChanged = times.locationChanged
    }

    func printHuman(indent: String) {
        let formatter = ISO8601DateFormatter()
        if let created {
            print("\(indent)Created: \(formatter.string(from: created))")
        }
        if let modified {
            print("\(indent)Modified: \(formatter.string(from: modified))")
        }
        if let accessed {
            print("\(indent)Accessed: \(formatter.string(from: accessed))")
        }
        if expires == true, let expiry {
            print("\(indent)Expires: \(formatter.string(from: expiry))")
        }
        if let usageCount, usageCount > 0 {
            print("\(indent)Usage count: \(usageCount)")
        }
    }
}

/// Path computation: walks the group tree looking for `entryUUID`, returns
/// the chain of group names that led to it (root group itself excluded).
/// Returns nil if the entry isn't in the tree.
enum GroupPath {
    static func find(
        entryUUID id: UUID,
        in group: KDBX.Group,
        prefix: [String]
    ) -> [String]? {
        for entry in group.entries where entry.uuid == id {
            return prefix
        }
        for child in group.groups {
            let childPrefix = prefix + [child.name ?? ""]
            if let found = find(entryUUID: id, in: child, prefix: childPrefix) {
                return found
            }
        }
        return nil
    }
}
