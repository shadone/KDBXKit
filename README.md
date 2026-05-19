<h1 align="center">KDBXKit</h1>

<p align="center">
  <strong>Read and write KeePass 2 (KDBX 4) databases from Swift.</strong><br/>
  Page-locked secrets, KeePassXC-tested round-trips, and streaming<br/>
  attachments that keep peak memory bounded regardless of vault size.
</p>

<p align="center">
  <a href="https://github.com/shadone/KDBXKit/actions/workflows/ci.yml"><img src="https://github.com/shadone/KDBXKit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Swift-6.1%2B-orange?logo=swift&logoColor=white" alt="Swift 6.1+">
  <img src="https://img.shields.io/badge/Platforms-macOS%2015%20%7C%20iOS%2018%20%7C%20Linux-blue" alt="Platforms">
  <img src="https://img.shields.io/badge/License-BSD%202--Clause-green" alt="License: BSD 2-Clause">
</p>

---

## What is KDBXKit?

KDBXKit is a Swift library for reading and writing [KeePass 2 / KDBX 4](https://keepass.info/help/kb/kdbx.html) password-manager databases — the format used by KeePass, KeePassXC, Strongbox, and similar clients. It handles the full file format (cryptographic envelope, KDF, inner XML, attachments) and exposes a typed Swift API with secure-memory primitives so consumers don't have to roll their own.

```swift
import KDBXKit

// Open
let data = try Data(contentsOf: url)
let unlock = UnlockData(masterPassword: "hunter2")
let content = try KDBXReader.parse(data, unlockData: unlock)

// Walk
content.database.visitEntries(in: content.database.root.group) { entry in
    print(entry.uuid, entry.strings.map(\.key))
}

// Save
let bytes = try KDBXWriter().write(content, unlockData: unlock)
try bytes.write(to: url)
```

## Features

| | |
|---|---|
| **Memory hygiene** | `SecureBytes` (mlock + secure-zero on deinit), `ProtectedString.withRevealedString` — no plaintext through `Swift.String` |
| **Streaming attachments** | lazy reader + streaming writer keep binaries off the heap; peak save memory is one attachment plus pipeline buffers, regardless of vault size |
| **Interop** | round-trip tested against KeePassXC `keepassxc-cli` (gated suite); malformed-input fuzz tests guard against crash-on-bad-data |
| **Concurrency** | Swift 6 strict-concurrency clean, all public types `Sendable` |
| **Supported versions** | KDBX 4.1, 4.0, KDBX 3.1 (read-only) |
| **Ciphers** | AES-256-CBC, ChaCha20 |
| **KDFs** | AES-KDF, Argon2d, Argon2id |
| **Inner stream** | Salsa20, ChaCha20 |
| **Compression** | gzip (system zlib) |
| **Key sources** | master password, key file, raw 32-byte pre-hash (e.g. biometric-unlocked Keychain) |

## Requirements

- **Swift**: 6.1+
- **macOS**: 15+
- **iOS**: 18+
- **Linux**: Swift 6.1 toolchain + zlib

## Installation

Add KDBXKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/shadone/KDBXKit.git", from: "1.0.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "KDBXKit", package: "KDBXKit"),
        ]
    ),
]
```

On Linux you also need zlib development headers:

```sh
sudo apt-get install zlib1g-dev    # Debian/Ubuntu
sudo dnf install zlib-devel        # Fedora
```

## Library usage

The basic open / walk / save flow is in the [intro snippet](#what-is-kdbxkit) above. A runnable end-to-end example lives in [`Examples/HelloKDBX/`](Examples/HelloKDBX/) — open it with `swift run HelloKDBX` for a working `.kdbx` reader in ~70 lines. The sections below cover the less obvious bits.

### Header-only inspection (no credentials)

```swift
let header = try KDBXReader.parseHeader(data)
print(header.formatVersion)        // .v4_1
print(header.kdfParameters)        // .argon2id(...)
print(header.encryptionAlgorithm)  // .AES256CBC / .ChaCha20
```

### Key files and biometric rehydration

```swift
// Password + key file
let unlock = UnlockData(masterPassword: "p", keyFile: keyFileBytes)

// Key file alone
let unlock = UnlockData(keyFile: keyFileBytes)

// Rehydrate from a Keychain-stored 32-byte pre-hash (biometric unlock)
let unlock = UnlockData(rawKeyData: keychainBytes)
```

The 32-byte pre-hash is the same authority as the password — protect it with appropriate access control on the storage side.

### Streaming attachments (large vaults)

For vaults whose attachments shouldn't sit resident from unlock to lock, open metadata-only and stream binaries on demand. `openMetadataOnly` runs the full decrypt + inner-header parse but drops the binary bytes; the returned `LazyKDBXContent` keeps a handle to the source so individual binaries can be re-streamed without holding all of them in memory.

```swift
let lazy = try KDBXReader.openMetadataOnly(from: .file(url), unlockData: unlock)

// Stream a specific binary into the destination of your choice.
var sink = try URLSink(writingTo: destination)  // or DataSink() / SecureBytesSink()
try KDBXReader.streamBinary(from: lazy, at: index, into: &sink)
```

To save without ever materializing all binaries in process memory, drive the streaming writer with `LazyBinarySource` (re-streamed from the source vault) and/or `DataBinarySource` (newly-added attachments still on the heap):

```swift
let content = KDBXContent(database: lazy.database, header: lazy.header, innerHeader: lazy.innerHeader)
let binaries: [any BinarySource] = lazy.binaries.indices.map { LazyBinarySource(lazy, at: $0) }
try KDBXWriter.streamingWrite(to: destinationURL, content: content, binaries: binaries, unlockData: unlock)
```

Peak save memory is one attachment plus the pipeline buffers (~64 KB gzip + ≤16 B AES + 1 MB HMAC block) — independent of total attachment bytes.

### Secure memory

Any cleartext key material crossing the library boundary is in `SecureBytes` (page-locked via `mlock`, zeroed via `memset_s` / `explicit_bzero` on deinit). Protected entry fields use a scoped-reveal pattern instead of returning raw strings:

```swift
// Find the entry's Password field — strings is [ProtectedString].
if let password = entry.strings.first(where: { $0.key == "Password" })?.value {
    password.withRevealedString { plaintext in
        // plaintext is a String that's about to leave scope; copy into the
        // platform secret store and return.
        Keychain.set(plaintext, for: entry.uuid)
    }
}
```

## Error handling

`KDBXReader.Error` and `KDBXWriter.Error` are typed enums with exhaustive cases — caller-facing doc comments on each case explain when it fires:

```swift
do {
    _ = try KDBXReader.parse(data, unlockData: unlock)
} catch KDBXReader.Error.wrongCredentials {
    // bad password / key file
} catch KDBXReader.Error.unsupportedFormatVersion(let major, let minor) {
    // file is KDBX \(major).\(minor) — outside our supported range
} catch KDBXReader.Error.corruptedHMAC(let reason) {
    // file failed integrity check
}
```

## Dependencies

External (all versioned, Apple-blessed, cross-platform):

- [`swift-crypto`](https://github.com/apple/swift-crypto) — SHA/HMAC, AES.
- [`swift-log`](https://github.com/apple/swift-log) — logging facade.
- [`swift-argument-parser`](https://github.com/apple/swift-argument-parser) — used by the companion CLI.

Vendored (in-tree, no network fetch):

- [P-H-C reference Argon2](https://github.com/P-H-C/phc-winner-argon2) in `Sources/CArgon2/` (pin: upstream commit `f57e61e`). CC0 / Apache 2.0 dual-licensed. See `Sources/CArgon2/UPSTREAM.md`.

System:

- `zlib` (linked via `-lz`, exposed to Swift via the `Sources/CZlib/` module). Ships with macOS; install `zlib1g-dev` or equivalent on Linux.

## Companion CLI: `kdbx`

The repo also ships a `kdbx` executable — a small debugging and scripting tool, also useful as a worked example of using the library.

```sh
swift run kdbx db info     <file.kdbx>                       # header-only, no creds needed
swift run kdbx entry ls    <file.kdbx> --password-stdin
swift run kdbx entry show  <file.kdbx> /Banking/Chase --password-stdin
swift run kdbx attach extract <file.kdbx> /Banking/Chase logo.png --password-stdin
```

Credentials never come from `argv`. Resolution order: `--password-stdin` → `KDBX_PASSWORD` env → `--key-file <path>` → no-echo TTY prompt. See [`Sources/KDBXCLICore/`](Sources/KDBXCLICore/) for the full subcommand tree and how the credential plumbing is structured.

## Development

### Build / test

```sh
swift build
swift test
swift test --filter HeaderTests
```

### Lint / format

[mint](https://github.com/yonaskolb/Mint) runs the Swift CLI tools listed in `Mintfile`.

```sh
brew install mint
mint bootstrap
mint run swiftformat --lint .   # check
mint run swiftformat .          # apply
```

### Testing the Linux build locally

You don't need a Linux machine — `scripts/test-linux.sh` runs the build and tests inside the same container CI uses. Requires Docker (Docker Desktop, Colima, or OrbStack).

```sh
./scripts/test-linux.sh                         # full build + test, Linux/arm64
./scripts/test-linux.sh --filter Header         # forwards args to `swift test`
SWIFT=6.2 ./scripts/test-linux.sh               # different toolchain
PLATFORM=linux/amd64 ./scripts/test-linux.sh    # x86_64 under qemu (slow)
```

Linux build artifacts land in `.build-linux/` (gitignored) so they don't collide with your macOS `.build/`; you can interleave runs freely.

Closer-to-CI alternative with [`act`](https://github.com/nektos/act):

```sh
brew install act
act -j linux            # run the workflow's Linux job locally
```

## Acknowledgements

- **Dominik Reichl** and the [KeePass](https://keepass.info) project for the KDBX 4 format specification and the canonical XML schema (`Sources/KDBXKit/Database/KDBX_XML.xsd`).
- **Alex Biryukov, Daniel Dinu, Dmitry Khovratovich** for the [Argon2](https://github.com/P-H-C/phc-winner-argon2) algorithm (winner of the Password Hashing Competition), and Dinu / Khovratovich / Aumasson / Neves for the reference C implementation we vendor in `Sources/CArgon2/`.
- The **[KeePassXC](https://keepassxc.org)** project — both for being a high-quality client we test interop against, and for the `keepassxc-cli` tool that makes round-trip testing tractable.
- **Apple's Swift Crypto team** for [swift-crypto](https://github.com/apple/swift-crypto), which carries all of our SHA / HMAC / AES work cross-platform.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
