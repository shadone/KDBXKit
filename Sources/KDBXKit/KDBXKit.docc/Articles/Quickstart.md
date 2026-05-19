# Quickstart

Open a vault, read it, change something, save it back.

## Overview

This is the smallest end-to-end use of KDBXKit — enough to read entries, mutate them, and write the result. For credential variations (key files, biometric rehydration) see ``UnlockData``. For large attachments see <doc:StreamingAttachments>.

## Opening a vault

```swift
import KDBXKit

let url = URL(filePath: "/path/to/vault.kdbx")
let data = try Data(contentsOf: url)
let unlock = UnlockData(masterPassword: "hunter2")
let content = try KDBXReader.parse(data, unlockData: unlock)
```

``KDBXReader/parse(_:unlockData:)`` is the static one-shot. It returns a fully-materialized ``KDBXContent`` — vault metadata, the entry/group tree, and any attachment binaries.

If you only need to inspect the file format (cipher, KDF, version) without unlocking, use ``KDBXReader/parseHeader(_:)`` — it doesn't require credentials.

```swift
let header = try KDBXReader.parseHeader(data)
print(header.formatVersion)        // .v4_1
print(header.encryptionAlgorithm)  // .AES256CBC / .ChaCha20
```

## Walking entries

``KDBXContent/database`` is the in-memory representation. The convenience traversal `visitEntries(in:_:)` walks the entire subtree:

```swift
content.database.visitEntries(in: content.database.root.group) { entry in
    let title = entry.strings.first(where: { $0.key == "Title" })?.value
    let user = entry.strings.first(where: { $0.key == "UserName" })?.value
    print(entry.uuid, title?.revealedString ?? "(no title)", user?.revealedString ?? "")
}
```

Entry strings are stored in the `strings` array — keyed by field name (`"Title"`, `"UserName"`, `"Password"`, `"URL"`, `"Notes"`, plus any custom strings). Standard fields and custom strings live in the same array.

## Reading a password safely

Passwords are ``KDBX/ProtectedString`` values — not raw strings. Access via the scoped-reveal closure:

```swift
if let pw = entry.strings.first(where: { $0.key == "Password" })?.value {
    pw.withRevealedString { plaintext in
        // plaintext lives only for the duration of this closure.
        keychain.set(plaintext, for: entry.uuid)
    }
}
```

The closure form bounds the lifetime of the cleartext `String`. See <doc:SecurityPrimitives> for the full memory-safety story.

## Mutating an entry

`KDBXContent` is a value type. Mutate it as you would any Swift struct:

```swift
var content = try KDBXReader.parse(data, unlockData: unlock)
var entry = content.database.root.group.entries[0]
entry.strings = entry.strings.map { string in
    if string.key == "Notes" {
        return KDBX.ProtectedString(key: "Notes", value: .regular("Updated by my app"))
    }
    return string
}
content.database.root.group.entries[0] = entry
```

For new entries, build them with the ``KDBX/Entry`` initializer and append to the target group's `entries` array.

## Saving

```swift
let writer = KDBXWriter()
let bytes = try writer.write(content, unlockData: unlock)
try bytes.write(to: url)
```

The writer regenerates random salts and IVs on every save by default — every save produces a different on-disk file even with identical content. For golden-file testing only, pass `regenerateSalts: false`.

If you'd rather not load the whole vault into memory just to save it back (typical when most entries are unchanged), see <doc:StreamingAttachments>.

## Wrong credentials

A wrong password / key file produces a typed error, not a crash:

```swift
do {
    _ = try KDBXReader.parse(data, unlockData: UnlockData(masterPassword: "wrong"))
} catch KDBXReader.Error.wrongCredentials {
    // Show "incorrect password" in your UI.
}
```

See <doc:ErrorHandling> for the full error surface.
