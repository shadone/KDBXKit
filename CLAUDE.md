# KDBXKit - CLAUDE.md

Guidance for Claude Code when working in the `KDBXKit/` repo (Swift library + `kdbx` CLI for KeePass 2.x / KDBX v4 files).
For repo-wide layout and the multi-repo version-control model, see `../CLAUDE.md`.

License: BSD 2-Clause (see `LICENSE`).

## Module layout

- `Sources/KDBXKit/` - the library
  - `KDBXReader.swift` / `KDBXWriter.swift` - main entry points for file I/O
  - `KDBXContent.swift` (+ `+Factory.swift`, `+validate.swift`) - top-level in-memory representation
  - `KDBXReader+Lazy.swift` / `LazyKDBXContent.swift` - lazy decryption path
  - `KDBXSource.swift` - abstraction over file / data / URL inputs
  - `Header/`, `InnerHeader/` - KDBX file format parsers
  - `KDBX/` - core data structures (`Entry`, `Group`, `Meta`, `Root`, `Times`, `AutoType`, `CustomIcon`, `ProtectedString`, `ProtectedBinary`, `DeletedObject`, etc.) plus per-type `+validate.swift`
  - `Crypto/` - `ChaCha20`, `Salsa20`, `AES256CBC` (in parent dir), `SecureBytes` (mlock + memset_s), `SecureRandom`, `ConstantTime`, `Encryptable`/`Decryptable` protocols
  - `KDF/` - `Argon2KDF`, `AESKDF`
  - `Database/` - XML schema (`KDBX_XML.xsd`) + XML-side helpers
  - `XML/` - XML reader/writer glue (over Nodal)
  - `Streaming/` - block-stream readers/writers
  - `HMACProtectedBlockStream.swift` - KDBX 4 outer block format
  - `AtomicFileWriter.swift` - write-temp + rename-into-place
  - `UnlockData.swift` - the 32-byte pre-hash representing an unlocked credential set
  - `MainKey.swift` - composite key derivation pipeline
  - `BinaryMetadata.swift`, `ByteSink.swift`, `CappedDataOutputStream.swift` - I/O helpers
  - `ValidationFailure.swift` - structured validation errors
- `Sources/KDBXCLICore/` - reusable CLI core (driven by `swift-argument-parser`). Contains `App.swift` root command, `Commands/` (one file per subcommand tree), `TreeMutator`, `RecycleBinManager`, `AddressResolver` (path resolution like `/Banking/Chase`), `EntryFieldOps`, `EntryHistory`, `VaultWriting`, `CredentialOptions` / `NewCredentialOptions` / `EntryPasswordOptions` / `SecretsOptions`, `OutputFormat`.
- `Sources/kdbx-cli/` - thin `@main` entry point that wires `KDBXCLICore.App` to `ArgumentParser`.
- `Tests/KDBXKitTests/` - 74 tests across crypto, header, KDF, encryption x KDF x compression matrix, key-file, malformed-input fuzz, validate, salt regeneration, SecureBytes. Fixtures in `Tests/KDBXKitTests/Resources/`.
- `Tests/KDBXCLICoreTests/` - covers `AddressResolver`, `EntryFilterPredicate`, `GroupPath`, `PathComponents`, `RecycleBin`, `RecycleBinManager`, `TreeMutator`, `EntryField`, `EntryHistory`, `SnapshotEncoder`, `VaultWriting`, plus end-to-end. `Fixtures.swift` builds synthetic `KDBX` trees in memory. `EndToEndTests.swift` drives `App.parseAsRoot([...])` on a tmp-file vault and uses `--key-file` to avoid stdin / TTY / env-var plumbing.

## Build & test

```bash
swift build                          # Build library + CLI
swift test                          # Run all 74+ tests
swift test --filter HeaderTests    # Run a specific suite
swift run kdbx --help              # Run CLI tool
mint run swiftformat .             # Format (run from this dir)
mint bootstrap                     # Install mint-managed tools (SwiftFormat)
```

**Swift Testing**, not XCTest. Use `@Suite("...")`, `@Test("...")`, `#expect(...)`.

Harmless warning: `Sources/KDBXKit/Database/KDBX_XML.xsd` triggers "found 1 file(s) which are unhandled" on every `swift build`.

## Dependencies

Declared in `Package.swift`:
- `CryptoSwift` - AES building blocks
- `swift-gzip` - inner XML compression
- `Nodal` - XML
- `argon2` - C library wrapper for Argon2 KDF
- `swift-argument-parser` - CLI

C++ interoperability is enabled for the crypto libraries.

## KDBX format handling - the API surface

### Eager read / write (one-shot, everything in memory)

- **`KDBXReader.parse(_:unlockData:)`** (static, one-shot) is the common case for callers that want a fully-materialized `KDBXContent`.
- **`KDBXReader.parseHeader(_:)`** (static) inspects a file without credentials.
- **Mutating form** `var reader = KDBXReader(data); try reader.parse(...)` exists for diagnostic access to `reader.header` / `reader.innerHeader` after a failure. Pass `retainsXMLForDiagnostics: true` to keep the decrypted XML around (default clears it on success - keeps plaintext out of process memory).
- **`KDBXWriter.write`** - byte-identical round-trip tests must pass `regenerateSalts: false`. The writer otherwise rolls fresh salts on every save, breaking `KDBXContent ==` on `header`.
- **`KDBXContent.parserWarnings: [String]`** accumulates silently-dropped XML elements/attributes during parse. Assert `== []` when adding a fixture from a third-party client to catch features we don't model.
- **`KDBXContent.makeEmpty(databaseName:kdf:)`** builds a fresh vault with modern defaults; **`KDFParameters.recommended(.fast / .balanced / .paranoid)`** for KDF profiles.

### Lazy read / streaming write (binaries stay on disk)

For vaults where the eager path's "every byte resident from unlock to lock" memory profile is unacceptable (large attachments), use the lazy / streaming pair. See `../SECURITY.md` C-10 for the security framing.

- **`KDBXReader.openMetadataOnly(from:unlockData:maxDecompressedPayloadSize:)`** runs the full decrypt + decompress + inner-header + XML parse, captures per-binary `(offset, length, isProtected, contentHash)` into `[BinaryMetadata]`, then drops the binary bytes. The returned `LazyKDBXContent` keeps the source + unlock key for on-demand re-streaming and is `Sendable` (crosses actor hops the same way `KDBXContent` does).
- **`KDBXReader.streamBinary(from:at:into:)`** reopens the source, replays decrypt + decompress to the target binary, and writes `length` bytes into the supplied `ByteSink`. The sink picks the destination: `DataSink` for unprotected access, `SecureBytesSink` for protected payloads (mlocked + zero-on-deinit, drain via `takeSecureBytes()`), `URLSink` for streaming straight to a destination file URL without ever materializing in `Data`.
- **`KDBXSource`** is the input abstraction — `.data(Data)` for tests / in-memory, `.file(URL)` for production. `.file` reads via `NSFileCoordinator` (read coordinator on every access), which interoperates with iCloud Drive writers. Nesting a `.file` read coordinator inside an outer `NSFileCoordinator` write block on the same URL deadlocks — design write paths to acquire the write coordinator only briefly (e.g. for an atomic temp→destination replace) and run streaming reads outside that scope.
- **`KDBXWriter.streamingWrite(to:content:binaries:unlockData:regenerateSalts:)`** is the streaming counterpart to `write`. Cleartext flows through a chain of `StreamingByteConsumer`s: `GzipStreamWriter` → `EncryptingStreamWriter` → `HMACBlockStreamWriter` → output `FileHandle`. Binaries are pulled one at a time via `[any BinarySource]`. Peak save memory is one attachment plus pipeline working buffers (~64 KB gzip + ≤16 B AES + 1 MB HMAC block), independent of total attachment bytes.
- **`BinarySource`** has two implementations: **`DataBinarySource`** (in-memory bytes, for fresh attachments awaiting their first save) and **`LazyBinarySource`** (re-streams a pool entry from a `LazyKDBXContent` — typical for unchanged attachments during a save where most binaries are still referenced by entries that didn't get edited).
- **Gzip implementation detail**: `Compression.OutputFilter(.compress, using: .zlib, …)` emits raw DEFLATE bytes (despite the algorithm being named `.zlib` — that's the library identifier, not the wrapper format). `GzipStreamWriter` prepends the 10-byte gzip header and appends an 8-byte CRC32+length trailer on top of the DEFLATE stream. CRC32 is computed incrementally over the uncompressed bytes via the small table in `CRC32.swift`.

### Format dialects we round-trip

- **Tags separator**: KeePassXC writes `,`-separated, KeePass 2 (.NET) writes `;`. Reader splits on either; writer emits `;` (matches the official KDBX 4.1 XSD). Tag values containing `;` or `,` round-trip lossily.

## Security primitives

- **`SecureBytes`** - page-locked (`mlock`), zero-on-deinit (`memset_s`). Any cleartext key material crossing this module must be `SecureBytes` or scoped through `withRevealedString { ... }` / `withRevealedBytes { ... }`, never `Swift.String`.
- **`ProtectedString.Value`** - access via `.withRevealedString { ... }` or `.bytes`; the old `.stringValue` getter is gone. When designing new APIs that surface protected fields, mirror this pattern - never return a raw `String`.
- **`ConstantTime`** - use for any comparison of secret-derived bytes.
- **`SecureRandom`** - canonical entropy source for salts, IVs, nonces.

## CLI (`kdbx`)

Nested subcommand structure (target `kdbx-cli`):
- `db {info, xml, validate, create, rekey, set-cipher, set-compression, set-kdf, empty-recycle-bin}`
- `entry {ls, show, add, set, rm, mv, history {ls, show, restore, prune}}`
- `group {ls, tree, add, set, rm, mv}`
- `attach {ls, extract, add, rm}`

### Credential handling

Credentials **never come from `argv`**. Accepted input channels:
- `--password-stdin` - read from stdin (one line, no trailing newline)
- `KDBX_PASSWORD` env var
- `--key-file <path>` - composite credential via key-file
- no-echo TTY prompt - interactive fallback when none of the above is set

`db info` works without credentials (header-only inspection).

**Entry-level passwords** use a separate channel so they don't collide with the master password's `--password-stdin`:
- `--entry-password-stdin`
- `--entry-password-prompt`

**New credentials** (`db create`, the new-credentials side of `db rekey`) go through `NewCredentialOptions` - `KDBX_PASSWORD` / `--password-stdin` are **ignored**. Pass `--new-password-stdin`, `--new-key-file <path>`, or run interactively.

### Mutating commands - safety rails

- First positional is always the vault path (e.g. `kdbx group add vault.kdbx Banking --in /`).
- `--backup` writes `<file>.kdbx.bak` before replacing in-place via `AtomicFileWriter`.
- `entry set` snapshots the prior state into `Entry.history` (trimmed by `Meta.historyMaxItems`) before mutating - pass `--no-history` to skip.
- `entry history restore --index N` is itself reversible because it pushes the live state onto history first.
- `entry set` / `group set` no-op when zero mutation flags were supplied (print "nothing to do", no rewrite, no `Times.lastModificationTime` bump). **Mirror this in new `*-set` commands.**

### Subcommand wiring gotcha

Bare `Set.self` in a `subcommands:` array collides with `Swift.Set<...>.Type`. Use `Entry.Set.self` / `Group.Set.self`. Other names (`Add`, `Rm`, `Mv`, `History`) resolve fine bare.

## Testing strategy

- Internal round-trip tests (read -> write -> read) prove **self-consistency, not interop correctness**. Three real bugs in the past slipped through internal round-trips and only surfaced via real-binary interop tests with KeePassXC: missing `<?xml version>` declaration, tag `;`-only emission, keyfile non-normalization.
- Round-trip tests that need byte-equality should pass `regenerateSalts: false` to `KDBXWriter.write` (default-on regen otherwise produces a byte-different file every save).
- When adding a fixture from a third-party client, assert `KDBXContent.parserWarnings == []` to catch features we don't model.

### Interop testing with KeePassXC

- CLI at `/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli`. Gate tests with `FileManager.isExecutableFile(atPath:)` so CI without it no-ops. Suite: `KeePassXCInteropTests`.
- `db-create` and `import` default to KDBX 3.1 - no flag bumps to 4.x. To produce a 4.x fixture, seed from an existing 4.x file (`cp Resources/simple-argon2id-aes256.kdbx target.kdbx`) and mutate, or build via XML and `merge` into a 4.x base.
- Pipe passwords with `(echo "$pw"; echo "$pw") | keepassxc-cli ...`. The password prompt is written to **stdout** - when capturing output, send stderr/stdout to different streams or the prompt ends up in your file.
- Bundled `Resources/kpxc-*.kdbx` fixtures use password `123` unless `KDBXTests.swift` notes otherwise (`kpxc-extras` is `test`).
- **`keepassxc-cli show` only prints the 5 standard fields + tags** - not custom strings, not expiry detail in every locale, not icons. Looks like a missing feature; isn't. The reliable interop pattern for any new field is: write via Passie -> force KeePassXC to re-encrypt by running `add -p <file> /Probe` (stdin gets two passwords: master + new-entry) -> re-open via Passie and assert the field round-tripped. See `PassieKeePassXCInteropTests` for the template.

## Cross-repo coordination

This library is consumed by `Passie/` (the iOS/macOS apps) via `.package(path: "../../KDBXKit")` in `Passie/Modules/Package.swift`. There's no submodule wiring.

- When a change spans both repos (e.g., new `SecureBytes` API consumed by `PassieData`), **land the KDBXKit side first**, then commit the Passie side referencing the new API.
- When designing a new KDBXKit type that the Passie UI layer will surface, expect `PassieData` to add a wrapper (e.g. `VaultUnlock` wraps `UnlockData`, `VaultKDFProfile` wraps `KDFParameters.Profile`) so `PassieUI` doesn't have to `import KDBXKit`. Keep new public types Sendable-clean.

## Platform requirements

- **Swift 6.1+** with strict concurrency enabled
- **C++ interoperability** for crypto libraries
- Builds for macOS, iOS 18+, and Linux (CI's responsibility - keep `#if canImport(...)` guards tight)

## Type / API gotchas

- `TypedIdentifier<T, V>` constructs via `init(rawValue:)`, e.g. `Vault.Identifier(rawValue: "id")` - there's no `.init()`. `TypedIdentifier` is not `Identifiable`.

## Tooling

- **Trust `swift build` / `swift test` over SourceKit `<new-diagnostics>`.** SourceKit reports phantom "Cannot find X in scope" errors on intra-module references that compile fine. The build is authoritative.
