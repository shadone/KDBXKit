//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Snapshot of every entry in a vault, ready to be emitted as either
/// human-readable text or JSON.
struct EntryListSnapshot: Encodable {
    let entries: [EntrySnapshot]

    init(
        rootGroup: KDBX.Group,
        innerHeader: InnerHeader,
        predicates: [EntryFilterPredicate],
        showSecrets: Bool
    ) {
        var collected: [EntrySnapshot] = []
        Self.visit(group: rootGroup) { entry in
            if predicates.allSatisfy({ $0.matches(entry) }) {
                collected.append(EntrySnapshot(
                    entry: entry,
                    innerHeader: innerHeader,
                    showSecrets: showSecrets
                ))
            }
        }
        entries = collected
    }

    private static func visit(group: KDBX.Group, _ visitor: (KDBX.Entry) -> Void) {
        for entry in group.entries {
            visitor(entry)
        }
        for child in group.groups {
            visit(group: child, visitor)
        }
    }

    func printHuman() {
        for snapshot in entries {
            print("")
            print("Entry: \(snapshot.uuid)")
            for field in snapshot.fields {
                print("\t\(field.key)\(field.humanTag): \(field.value)")
            }
            if !snapshot.binaries.isEmpty {
                print("\tBinaries:")
                for binary in snapshot.binaries {
                    switch binary.source {
                    case .inline:
                        print("\t\t\(binary.key): \(binary.size) bytes")
                    case .ref:
                        print("\t\t\(binary.key): ref=\(binary.ref ?? 0): \(binary.size) bytes")
                    }
                }
            }
        }
    }
}

struct EntrySnapshot: Encodable {
    let uuid: String
    let fields: [FieldSnapshot]
    let binaries: [BinarySnapshot]

    init(entry: KDBX.Entry, innerHeader: InnerHeader, showSecrets: Bool) {
        uuid = entry.uuid.uuidString
        fields = entry.strings.map { FieldSnapshot($0, showSecrets: showSecrets) }
        binaries = entry.binaries.map { binary in
            BinarySnapshot(binary: binary, innerHeader: innerHeader)
        }
    }
}

struct FieldSnapshot: Encodable {
    enum Protection: String, Encodable {
        case regular
        case unprotected
        case protectedInMemory
        case lazyInnerCipher

        /// On-disk protected fields are what `--show-secrets` gates.
        /// `regular` fields (Title, URL, UserName by convention) are not
        /// considered secret; KDBX writers stored them plaintext.
        var isOnDiskProtected: Bool {
            switch self {
            case .regular: return false
            case .unprotected, .protectedInMemory, .lazyInnerCipher: return true
            }
        }
    }

    let key: String
    let value: String
    let protection: Protection
    let masked: Bool

    init(_ kv: KDBX.ProtectedString, showSecrets: Bool) {
        key = kv.key
        let rawValue: String
        switch kv.value {
        case let .regular(b):
            rawValue = b.revealedString
            protection = .regular
        case let .unprotected(b):
            rawValue = b.revealedString
            protection = .unprotected
        case let .protectedInMemory(b):
            rawValue = b.revealedString
            protection = .protectedInMemory
        case .lazyInnerCipher:
            rawValue = kv.value.revealedString
            protection = .lazyInnerCipher
        }
        if protection.isOnDiskProtected, !showSecrets {
            value = maskedFieldPlaceholder
            masked = true
        } else {
            value = rawValue
            masked = false
        }
    }

    /// Tag appended after the field name in human output. Empty for plain
    /// fields; `[*]` for secrets stored unencrypted on disk (a smell);
    /// `[M]` for in-memory-only protected fields.
    var humanTag: String {
        switch protection {
        case .regular: return ""
        case .unprotected, .lazyInnerCipher: return "[*]"
        case .protectedInMemory: return "[M]"
        }
    }
}

struct BinarySnapshot: Encodable {
    enum Source: String, Encodable {
        case inline
        case ref
    }

    let key: String
    let source: Source
    let size: Int
    let ref: UInt32?
    /// True when `ref` points outside the binary pool. The library
    /// intentionally parses such vaults (validation warning only), so
    /// read-only commands must report the corruption, not trap on the
    /// out-of-range subscript.
    let dangling: Bool

    init(binary: KDBX.ProtectedBinary, innerHeader: InnerHeader) {
        key = binary.key
        switch binary.value {
        case let .inline(data, _):
            source = .inline
            size = data.count
            ref = nil
            dangling = false
        case let .ref(idx):
            source = .ref
            ref = idx
            if Int(idx) < innerHeader.binaryContent.count {
                size = innerHeader.binaryContent[Int(idx)].data.count
                dangling = false
            } else {
                size = 0
                dangling = true
            }
        }
    }
}
