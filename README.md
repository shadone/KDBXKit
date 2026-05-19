# KDBXKit

Swift library and `kdbx` CLI for reading and writing KeePass 2.x database files (KDBX v4).

## Status at a glance

| | |
|---|---|
| **Read** | KDBX 3.1, 4.0, 4.1 |
| **Write** | KDBX 4.1 (3.x files migrate on save; see `LegacyFormatNotice`) |
| **Ciphers** | AES-256-CBC, ChaCha20 |
| **KDFs** | AES-KDF, Argon2d, Argon2id |
| **Inner stream** | Salsa20, ChaCha20 |
| **Compression** | gzip (system zlib) |
| **Key sources** | master password, key file, raw 32-byte pre-hash (e.g. biometric-unlocked Keychain) |
| **Memory hygiene** | `SecureBytes` (mlock + secure-zero on deinit), `ProtectedString.withRevealedString` |
| **Concurrency** | Swift 6 strict concurrency, all public types `Sendable` |
| **Platforms** | macOS 15+, iOS 18+, Linux (Swift 6.1+ + zlib) |
| **License** | BSD 2-Clause |

## Install

Add KDBXKit to your `Package.swift`:

```swift
.package(url: "https://github.com/shadone/KDBXKit.git", branch: "develop"),
```

…and depend on the `KDBXKit` product from any target:

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "KDBXKit", package: "KDBXKit"),
    ]
),
```

On Linux you'll also need zlib development headers:

```sh
sudo apt-get install zlib1g-dev    # Debian/Ubuntu
sudo dnf install zlib-devel        # Fedora
```

## Library usage

```swift
import KDBXKit

// Open
let data = try Data(contentsOf: url)
var reader = KDBXReader(data)
let content = try reader.parse(unlockData: .init(masterPassword: "secret"))

// Walk
content.database.visitEntries(in: content.database.root.group) { entry in
    print(entry.uuid, entry.strings.map(\.key))
}

// Save
let writer = KDBXWriter()
let bytes = try writer.write(content, unlockData: unlock)
try bytes.write(to: url)
```

For large attachments where loading every binary into RAM is wasteful, use the lazy read / streaming write pair:

```swift
let lazyContent = try KDBXReader.openMetadataOnly(from: .file(url), unlockData: unlock)
// `lazyContent` keeps binaries on disk; stream individual ones via streamBinary(...)

try KDBXWriter().streamingWrite(
    to: destinationURL,
    content: lazyContent.content,
    binaries: lazyContent.binaries,
    unlockData: unlock
)
```

## CLI

The `kdbx` executable ships alongside the library:

```sh
swift run kdbx db info  <file.kdbx>                       # header-only, no creds needed
swift run kdbx db xml   <file.kdbx> --password-stdin      # full XML dump
swift run kdbx entry ls <file.kdbx> --password-stdin      # list entries
swift run kdbx entry show <file.kdbx> /Banking/Chase --password-stdin
```

Credentials never come from `argv`. Resolution order: `--password-stdin` →
`KDBX_PASSWORD` env (suppress with `--no-env`) → `--key-file <path>` →
no-echo TTY prompt. Add `--key-file <path>` to any of the above to combine
key-file material with a master password.

Mutating commands (`entry set`, `group add`, `db rekey`, …) accept `--backup` to write `<file>.kdbx.bak` before replacing in-place via `AtomicFileWriter`.

## Dependencies

External (all versioned and Apple-blessed):

- [`swift-crypto`](https://github.com/apple/swift-crypto) — SHA/HMAC, AES.
- [`swift-log`](https://github.com/apple/swift-log) — logging facade.
- [`swift-argument-parser`](https://github.com/apple/swift-argument-parser) — CLI.

Vendored:

- [P-H-C reference Argon2](https://github.com/P-H-C/phc-winner-argon2) in `Sources/CArgon2/` (pin: upstream commit `f57e61e`). License: CC0 / Apache 2.0 dual. See `Sources/CArgon2/UPSTREAM.md`.

System:

- `zlib` (linked via `-lz`). Available on macOS by default; install `zlib1g-dev` or equivalent on Linux.

## Development

### Build / test

```sh
swift build
swift test
swift test --filter HeaderTests
```

### Format

[mint](https://github.com/yonaskolb/Mint) runs Swift CLI tools listed in `Mintfile`.

```sh
brew install mint
mint bootstrap
mint run swiftformat .
```

### Testing the Linux build locally

You don't need a Linux machine to verify the Linux path — `scripts/test-linux.sh` runs the build and tests inside the same Swift container CI uses. Requires Docker (Docker Desktop, Colima, or OrbStack).

```sh
./scripts/test-linux.sh                  # full build + test, Linux/arm64
./scripts/test-linux.sh --filter Header  # forward args to `swift test`
SWIFT=6.2 ./scripts/test-linux.sh        # try a different toolchain
PLATFORM=linux/amd64 ./scripts/test-linux.sh   # cross-test x86_64 under qemu (slow)
```

Linux build artifacts go into `.build-linux/` (gitignored) so they don't collide with your macOS `.build/`; you can interleave macOS and Linux `swift test` runs freely.

### Running the GitHub Actions workflow locally with `act`

For the closer-to-CI experience, [`act`](https://github.com/nektos/act) executes `.github/workflows/ci.yml` against local Docker:

```sh
brew install act      # one-time
act -j linux          # run just the Linux job
act -j macos          # run just the macOS job (best-effort — see act's caveats)
act                   # run everything (PR event by default)
```

On Apple Silicon you may need `--container-architecture linux/amd64` if `act`'s default image is amd64-only. Our Linux job uses the `swift:6.1-jammy` container directly so the host image doesn't matter much.

### CI

`.github/workflows/ci.yml` runs three jobs on every push / PR to `develop`:

- **macOS 15** — `swift build` + `swift test`.
- **Linux** — `swift build` + `swift test` in `swift:6.1-jammy`.
- **SwiftFormat lint**.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
