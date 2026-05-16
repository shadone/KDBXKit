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

    init(content: KDBXContent) {
        var collected: [EntrySnapshot] = []
        content.database.visitEntries(in: content.database.root.group) { entry in
            collected.append(EntrySnapshot(entry: entry, innerHeader: content.innerHeader))
        }
        entries = collected
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

    init(entry: KDBX.Entry, innerHeader: InnerHeader) {
        uuid = entry.uuid.uuidString
        fields = entry.strings.map(FieldSnapshot.init)
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
    }

    let key: String
    let value: String
    let protection: Protection

    init(_ kv: KDBX.ProtectedString) {
        key = kv.key
        switch kv.value {
        case let .regular(b):
            value = b.revealedString
            protection = .regular
        case let .unprotected(b):
            value = b.revealedString
            protection = .unprotected
        case let .protectedInMemory(b):
            value = b.revealedString
            protection = .protectedInMemory
        case .lazyInnerCipher:
            value = kv.value.revealedString
            protection = .lazyInnerCipher
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

    init(binary: KDBX.ProtectedBinary, innerHeader: InnerHeader) {
        key = binary.key
        switch binary.value {
        case let .inline(data):
            source = .inline
            size = data.count
            ref = nil
        case let .ref(idx):
            source = .ref
            let data = innerHeader.binaryContent[Int(idx)].data
            size = data.count
            ref = idx
        }
    }
}
