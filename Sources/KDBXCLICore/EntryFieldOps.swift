//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Field-level helpers used by `entry add` and `entry set`. KDBX entries
/// keep both standard fields (Title, UserName, URL, Notes, Password) and
/// arbitrary custom fields in the same `strings` array — these helpers
/// hide that flat representation behind named ops.
enum EntryField {
    /// Canonical names for the five standard fields. Anything else is a
    /// custom field.
    static let title = "Title"
    static let userName = "UserName"
    static let url = "URL"
    static let notes = "Notes"
    static let password = "Password"

    static let standardKeys: Set<String> = [title, userName, url, notes, password]

    /// Set or replace a regular (plaintext-on-disk) field. Used for Title /
    /// UserName / URL / Notes / non-protected custom fields.
    static func setRegular(_ key: String, _ value: String, on entry: inout KDBX.Entry) {
        upsert(key: key, value: .regular(value), on: &entry)
    }

    /// Set or replace an unprotected-on-write field. Used for Password and
    /// any custom field that should be written inner-cipher-encrypted on
    /// save. (`.unprotected` is the case the writer treats as
    /// `Protected="True"` — see ProtectedString.Value docs.)
    static func setProtected(_ key: String, _ value: String, on entry: inout KDBX.Entry) {
        upsert(key: key, value: .unprotected(value), on: &entry)
    }

    /// Remove a field by key. Returns true if a field was removed.
    @discardableResult
    static func remove(_ key: String, from entry: inout KDBX.Entry) -> Bool {
        if let idx = entry.strings.firstIndex(where: { $0.key == key }) {
            entry.strings.remove(at: idx)
            return true
        }
        return false
    }

    private static func upsert(
        key: String,
        value: KDBX.ProtectedString.Value,
        on entry: inout KDBX.Entry
    ) {
        if let idx = entry.strings.firstIndex(where: { $0.key == key }) {
            entry.strings[idx] = KDBX.ProtectedString(key: key, value: value)
        } else {
            entry.strings.append(KDBX.ProtectedString(key: key, value: value))
        }
    }
}

/// Parsed `<key>=<value>` argument. Same shape that `entry ls --filter`
/// uses, except here the value is the full custom-field content (not a
/// substring needle), so we don't lowercase it.
struct EntryFieldAssignment {
    let key: String
    let value: String

    static func parse(_ raw: String) throws -> EntryFieldAssignment {
        guard let eq = raw.firstIndex(of: "=") else {
            throw EntryFieldAssignmentError.malformed(raw)
        }
        let key = String(raw[..<eq])
        let value = String(raw[raw.index(after: eq)...])
        if key.isEmpty {
            throw EntryFieldAssignmentError.malformed(raw)
        }
        return EntryFieldAssignment(key: key, value: value)
    }
}

enum EntryFieldAssignmentError: Error, CustomStringConvertible {
    case malformed(String)
    case standardFieldNotAllowed(String)

    var description: String {
        switch self {
        case let .malformed(raw):
            return "Bad field assignment `\(raw)`. Expected <key>=<value> with a non-empty key."
        case let .standardFieldNotAllowed(key):
            return "`\(key)` is a standard KDBX field — set it with --\(Self.standardFlagName(for: key)) instead of --field."
        }
    }

    private static func standardFlagName(for key: String) -> String {
        switch key {
        case EntryField.title: return "title"
        case EntryField.userName: return "username"
        case EntryField.url: return "url"
        case EntryField.notes: return "notes"
        case EntryField.password: return "entry-password-stdin / --entry-password-prompt"
        default: return key.lowercased()
        }
    }
}
