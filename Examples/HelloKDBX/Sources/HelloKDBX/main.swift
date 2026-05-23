// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// HelloKDBX — a minimal example of opening a KDBX vault, walking the
// group tree, and revealing protected fields.
//
// Run:
//   swift run HelloKDBX                  # uses ./demo.kdbx (password: "demo")
//   swift run HelloKDBX path/to/vault.kdbx
//
// The vault password is hard-coded here for demonstration. A real
// application would read it from a TTY prompt or a secure source.

import Foundation
import KDBXKit

let defaultVault = "demo.kdbx"
let defaultPassword = "demo"

let url = URL(filePath: CommandLine.arguments.count >= 2
    ? CommandLine.arguments[1]
    : defaultVault)

guard FileManager.default.fileExists(atPath: url.path) else {
    print("Vault not found at \(url.path)")
    print("Usage: HelloKDBX [path/to/vault.kdbx]")
    print("Defaults to ./\(defaultVault) (password: \"\(defaultPassword)\")")
    exit(1)
}

// 1. Parse the encrypted vault.
//
// `KDBXReader.parse` runs the KDF (Argon2id by default — slow on
// purpose), verifies header and block-stream HMACs, decrypts the
// payload, and returns a fully materialised `KDBXContent`.
let data = try Data(contentsOf: url)
let unlock = UnlockData(masterPassword: defaultPassword)
let content = try KDBXReader.parse(data, unlockData: unlock)

// 2. Inspect the database.
print("Opened \(url.lastPathComponent)")
if let name = content.database.meta.databaseName {
    print("Name:   \(name)")
}

print("Cipher: \(content.header.encryptionAlgorithm)")
print("KDF:    \(content.header.kdfParameters)")
print()

// 3. Walk the group tree, printing entries and revealing protected
//    fields.
walk(content.database.root.group, indent: 0)

func walk(_ group: KDBX.Group, indent: Int) {
    let pad = String(repeating: "  ", count: indent)
    print("\(pad)[\(group.name ?? "(unnamed)")]")

    for entry in group.entries {
        let title = standardValue(entry, "Title") ?? "(untitled)"
        print("\(pad)  - \(title)")
        printField(entry, "UserName", pad + "      ")
        printField(entry, "URL", pad + "      ")
        printField(entry, "Notes", pad + "      ")
        printField(entry, "Password", pad + "      ")

        // Any custom fields the user added beyond the standard five.
        // KDBXKit doesn't distinguish "standard" from "custom" — it's
        // just a list of named String entries. Custom fields can be
        // protected too (e.g. a TOTP secret).
        let standardKeys: Set<String> = ["Title", "UserName", "URL", "Notes", "Password"]
        for s in entry.strings where !standardKeys.contains(s.key) {
            // `withRevealedString` materialises the cleartext only
            // for the lifetime of the closure, then drops it.
            s.value.withRevealedString { plaintext in
                print("\(pad)      [\(s.key)] = \(plaintext)")
            }
        }

        if !entry.binaries.isEmpty {
            let names = entry.binaries.map(\.key).joined(separator: ", ")
            print("\(pad)      attachments: \(names)")
        }
    }

    for child in group.groups {
        walk(child, indent: indent + 1)
    }
}

func standardValue(_ entry: KDBX.Entry, _ key: String) -> String? {
    entry.strings.first(where: { $0.key == key })?.value.revealedString
}

func printField(_ entry: KDBX.Entry, _ key: String, _ pad: String) {
    guard let s = entry.strings.first(where: { $0.key == key }) else { return }
    s.value.withRevealedString { value in
        guard !value.isEmpty else { return }
        print("\(pad)\(key): \(value)")
    }
}
