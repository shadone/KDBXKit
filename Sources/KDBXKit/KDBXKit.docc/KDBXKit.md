# ``KDBXKit``

Read and write KeePass 2 (KDBX 4) databases from Swift.

## Overview

KDBXKit is a Swift library for handling KeePass 2 / KDBX 4 password-manager databases — the format used by KeePass, KeePassXC, Strongbox, and similar clients. It handles the full file format (cryptographic envelope, KDF, inner XML, attachments) and exposes a typed Swift API with secure-memory primitives so consumers don't have to roll their own.

```swift
import KDBXKit

let data = try Data(contentsOf: url)
let unlock = UnlockData(masterPassword: "hunter2")
let content = try KDBXReader.parse(data, unlockData: unlock)

content.database.visitEntries(in: content.database.root.group) { entry in
    print(entry.uuid, entry.strings.map(\.key))
}

let bytes = try KDBXWriter().write(content, unlockData: unlock)
try bytes.write(to: url)
```

### What KDBXKit gives you beyond a parser

- **Page-locked secret storage.** Cleartext key material lives in ``SecureBytes`` — `mlock`'d against swap, zeroed on `deinit` with `memset_s` / `explicit_bzero`. No plaintext leaks through `Swift.String`.
- **Scoped reveal for protected fields.** ``KDBX/ProtectedString`` values use `withRevealedString { … }` rather than getters, bounding plaintext lifetime to a closure scope.
- **Streaming attachments.** ``KDBXReader/openMetadataOnly(from:unlockData:maxDecompressedPayloadSize:)`` reads the metadata without loading binaries; ``KDBXWriter/streamingWrite(to:content:binaries:unlockData:regenerateSalts:)`` writes back without materializing them. Peak save memory is independent of vault size.
- **HMAC-before-decrypt ordering.** Vault integrity is verified before any post-decrypt processing — wrong-key attempts never feed garbage to zlib or the XML parser.
- **Crash-free on malformed input.** Adversarial files fail with a typed ``KDBXReader/Error``, not a `fatalError`.
- **KeePassXC interop tested.** A gated suite drives the real `keepassxc-cli` against vaults we wrote and back.

## Topics

### Articles

- <doc:Quickstart>
- <doc:StreamingAttachments>
- <doc:SecurityPrimitives>
- <doc:ErrorHandling>

### Reading

- ``KDBXReader``
- ``KDBXContent``
- ``LazyKDBXContent``
- ``KDBXSource``
- ``BinaryMetadata``

### Writing

- ``KDBXWriter``
- ``BinarySource``
- ``DataBinarySource``
- ``LazyBinarySource``

### Credentials

- ``UnlockData``
- ``UnlockDataError``

### Sinks for streamed binaries

- ``ByteSink``
- ``DataSink``
- ``SecureBytesSink``
- ``URLSink``

### Secure memory

- ``SecureBytes``

### KDBX content tree

- ``KDBX``
- ``InnerHeader``
- ``Header``

### Atomic file replacement

- ``AtomicFileWriter``
