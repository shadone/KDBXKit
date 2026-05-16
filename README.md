# KDBXKit

Swift API for reading and writing KeePass 2.x database files (KDBX v4).

Supports:

- KDBX v4 header / inner-header parsing and serialization
- ChaCha20, Salsa20, AES-256-CBC ciphers
- Argon2 and AES-KDF key derivation
- HMAC-protected block streams, gzip-compressed inner XML
- High-level access to entries, groups, and metadata

Requires Swift 6.1+, iOS 18+, macOS 15+.

## Library usage

```swift
import KDBXKit

let data = try Data(contentsOf: url)
var reader = KDBXReader(data)
let content = try reader.parse(unlockData: .init(masterPassword: "secret"))

content.database.visitEntries(in: content.database.root.group) { entry in
    print(entry.uuid, entry.strings.map(\.key))
}
```

To write a database back:

```swift
let writer = KDBXWriter()
let bytes = try writer.write(content, unlockData: unlock)
try bytes.write(to: url)
```

## CLI

A `kdbx` executable is shipped alongside the library:

```sh
swift run kdbx db info  <file.kdbx>                       # header-only, no creds needed
swift run kdbx db xml   <file.kdbx> --password-stdin      # full XML dump
swift run kdbx entry ls <file.kdbx> --password-stdin      # list entries
```

Credentials never come from `argv`. Resolution order: `--password-stdin` →
`KDBX_PASSWORD` env (suppress with `--no-env`) → `--key-file <path>` →
no-echo TTY prompt. Add `--key-file <path>` to any of the above to combine
key-file material with a master password.

## Development

### Install `mint`

[mint](https://github.com/yonaskolb/Mint) runs Swift CLI tools listed in `Mintfile`.

```sh
brew install mint
mint bootstrap
```

### Format

```sh
mint run swiftformat .
```

### Build / test

```sh
swift build
swift test
swift test --filter HeaderTests
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).
