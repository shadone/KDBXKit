# KDBXKit - CLAUDE.md

Guidance for Claude Code when working in the `KDBXKit/` repo (Swift library + `kdbx` CLI for KeePass 2.x / KDBX v4 files).
For repo-wide layout and the multi-repo version-control model, see `../CLAUDE.md`.

License: BSD 2-Clause (see `LICENSE`). The repo is [REUSE](https://reuse.software) 3.3-compliant — every file declares copyright + an SPDX identifier, enforced by `.github/workflows/reuse.yml`. New Swift sources need the standard header (`// Copyright (c) <year>, Denis Dzyubenko <denis@ddenis.info>` + `// SPDX-License-Identifier: BSD-2-Clause`); the CryptoSwift-derived `Crypto/Salsa20.swift` + `Crypto/ChaCha20.swift` are `Zlib` (keep their notice intact); vendored `Sources/CArgon2/**` (`CC0-1.0 OR Apache-2.0`), the Reichl `KDBX_XML.xsd` (BSD-2-Clause), and binary fixtures are declared in `REUSE.toml`. License texts live in `LICENSES/`. Verify with `uvx reuse lint` (or `pipx run reuse lint`).

## Module layout

- `Sources/KDBXKit/` - the library
  - `KDBXReader.swift` / `KDBXWriter.swift` - main entry points for file I/O. **Writer has two paths**: eager `KDBXWriter.write` and `streamingWrite` (in `Streaming/KDBXWriter+Streaming.swift`, the production save path on Apple platforms). Serialization-level invariants (format clamps, salt regen) must be applied to **both** - a regression in one isn't visible from the other's tests.
  - `KDBXContent.swift` (+ `+Factory.swift`, `+validate.swift`) - top-level in-memory representation
  - `KDBXReader+Lazy.swift` / `LazyKDBXContent.swift` - lazy decryption path
  - `KDBXSource.swift` - abstraction over file / data / URL inputs
  - `Header/`, `InnerHeader/` - KDBX file format parsers
  - `KDBX/` - core data structures (`Entry`, `Group`, `Meta`, `Root`, `Times`, `AutoType`, `CustomIcon`, `ProtectedString`, `ProtectedBinary`, `DeletedObject`, etc.) plus per-type `+validate.swift`
  - `Crypto/` - `ChaCha20`, `Salsa20`, `AES256CBC` (in parent dir), `SecureBytes` (mlock + `memset_s` on Apple/BSD, `explicit_bzero` on Linux) backed by `SecureBytesArena` (shared page-aligned mlock'd 64 KiB arenas so N small secrets pack into a few wired pages instead of one page each), `SecureRandom`, `ConstantTime`, `Encryptable`/`Decryptable` protocols
  - `KDF/` - `Argon2KDF` (over the in-tree `argon2` C target — see `Sources/CArgon2/`), `AESKDF`
  - `Database/` - XML schema (`KDBX_XML.xsd`) + XML-side helpers
  - `XML/` - XML reader/writer glue
  - `Streaming/` - block-stream readers/writers; `Zlib.swift` is the push-based gzip compressor + one-shot decompressor over system zlib (`-lz`)
  - `HMACProtectedBlockStream.swift` - KDBX 4 outer block format
  - `AtomicFileWriter.swift` - write-temp + rename-into-place
  - `UnlockData.swift` - the 32-byte pre-hash representing an unlocked credential set
  - `MainKey.swift` - composite key derivation pipeline
  - `BinaryMetadata.swift`, `ByteSink.swift` - I/O helpers
  - `ValidationFailure.swift` - structured validation errors
- `Sources/KDBXCLICore/` - reusable CLI core (driven by `swift-argument-parser`). Contains `App.swift` root command, `Commands/` (one file per subcommand tree), `TreeMutator`, `RecycleBinManager`, `AddressResolver` (path resolution like `/Banking/Chase`), `EntryFieldOps`, `EntryHistory`, `VaultWriting`, `CredentialOptions` / `NewCredentialOptions` / `EntryPasswordOptions` / `SecretsOptions`, `OutputFormat`.
- `Sources/kdbx-cli/` - thin `@main` entry point that wires `KDBXCLICore.App` to `ArgumentParser`.
- `Tests/KDBXKitTests/` - ~225 tests across crypto, header, KDF, encryption x KDF x compression matrix, key-file, malformed-input fuzz, validate, salt regeneration, SecureBytes, KeePassXC interop (gated on `keepassxc-cli` availability — see `KeePassXCInteropTests`). Fixtures in `Tests/KDBXKitTests/Resources/`.
- `Tests/KDBXCLICoreTests/` - covers `AddressResolver`, `EntryFilterPredicate`, `GroupPath`, `PathComponents`, `RecycleBin`, `RecycleBinManager`, `TreeMutator`, `EntryField`, `EntryHistory`, `SnapshotEncoder`, `VaultWriting`, plus end-to-end. `Fixtures.swift` builds synthetic `KDBX` trees in memory. `EndToEndTests.swift` drives `App.parseAsRoot([...])` on a tmp-file vault and uses `--key-file` to avoid stdin / TTY / env-var plumbing.

## Build & test

```bash
swift build                          # Build library + CLI (macOS)
swift test                          # Run all tests (macOS)
swift test --filter HeaderTests    # Run a specific suite
swift run kdbx --help              # Run CLI tool
mint run swiftformat .             # Format (run from this dir)
mint bootstrap                     # Install mint-managed tools (SwiftFormat)

swift package generate-documentation --target KDBXKit  # Build the DocC archive.
                                   # Catches broken symbol links + missing summaries
                                   # before CI does. Output: .build/plugins/Swift-DocC/outputs/.

./scripts/test-linux.sh            # Build + test in the swift:6.1-jammy container CI uses.
                                   # Linux artifacts land in .build-linux (gitignored) so
                                   # macOS .build stays untouched. Forwards extra args to
                                   # `swift test`, e.g. ./scripts/test-linux.sh --filter Header.
act -j linux                       # Same idea via nektos/act: runs the actual CI workflow's
                                   # Linux job against local Docker. Heavier; reach for it
                                   # when debugging the workflow itself rather than the code.

Fuzz/run-fuzz.sh <header|parse|xml|variantdict|blockstream> [secs]
                                   # Coverage-guided libFuzzer campaign, run in Docker. macOS
                                   # toolchains CANNOT build libFuzzer (Xcode rejects
                                   # -sanitize=fuzzer; swift.org needs fragile hacks), so it runs
                                   # on Linux. Targets are gated behind KDBXKIT_FUZZ=1 and are
                                   # absent from a normal build/test/Xcode. Crashers land in
                                   # Fuzz/crashers/<t>/ and are replayed by FuzzRegressionTests in
                                   # plain `swift test`. See Fuzz/README.md.
```

**Swift Testing**, not XCTest. Use `@Suite("...")`, `@Test("...")`, `#expect(...)`.

## Dependencies

Declared in `Package.swift`:
- `swift-crypto` (`Crypto` + `_CryptoExtras`) - SHA/HMAC, AES-CBC + single-block AES (used by `AESKDF` and the eager + streaming CBC paths). Cross-platform.
- `swift-log` - logging facade; library code emits via `Logger(label:)`, host bootstraps a backend (os.Logger on Apple, `StreamLogHandler` on Linux).
- `swift-argument-parser` - CLI.

In-tree (not external):
- `Sources/CArgon2/` - vendored P-H-C reference Argon2 (pin: upstream commit `f57e61e`, 2021-06-25). Target name `argon2`, so `import argon2` works unchanged. Sources are CC0 / Apache 2.0 dual; `LICENSE` + `UPSTREAM.md` document the pin.

System libraries:
- `zlib` - gzip compress + decompress for the inner payload. Exposed to Swift via a small `Sources/CZlib/` system-library target (`module.modulemap` + shim header) that declares `link "z"` in the map. `Sources/KDBXKit/Streaming/Zlib.swift` is the push-based wrapper that uses `CZlib`.
- `pthread` - transitively required by argon2's `thread.c`; auto-linked on Apple, comes via swift runtime on Linux.

## Format specification (authoritative for byte-level questions)

- `docs/spec/kdbx-container.md` — outer binary container (signature → inner header). Includes Argon2id / HMAC / block-stream test vectors against `Tests/KDBXKitTests/Resources/simple-argon2id-aes256.kdbx`.
- `docs/spec/kdbx-xml.md` — inner XML payload. Cross-references the container spec.
- `docs/spec/KDBX_XML.xsd` — canonical schema (Dominik Reichl, BSD). Reference-only; not built or bundled.

Both prose docs are normative downstream of the official KeePass implementation: where they conflict, the official implementation wins. Cite the spec from code when a format decision is non-obvious; update the spec when a real divergence is found.

## KDBX format handling - the API surface

### Eager read / write (one-shot, everything in memory)

- **`KDBXReader.parse(_:unlockData:)`** (static, one-shot) is the common case for callers that want a fully-materialized `KDBXContent`.
- **`KDBXReader.parseHeader(_:)`** (static) inspects a file without credentials.
- **Mutating form** `var reader = KDBXReader(data); try reader.parse(...)` exists for diagnostic access to `reader.header` / `reader.innerHeader` after a failure. Pass `retainsXMLForDiagnostics: true` to keep the decrypted XML around (default clears it on success - keeps plaintext out of process memory).
- **`KDBXWriter.write`** - byte-identical round-trip tests must pass `regenerateSalts: false`. The writer otherwise rolls fresh salts on every save, breaking `KDBXContent ==` on `header`.
- **`KDBXContent.parserWarnings: [String]`** accumulates silently-dropped XML elements/attributes during parse. Assert `== []` when adding a fixture from a third-party client to catch features we don't model.
- **`KDBXContent.makeEmpty(databaseName:kdf:)`** builds a fresh vault with modern defaults. The `kdf:` parameter takes a `KDFParameters` value and defaults to **`KDFParameters.argon2idDefault()`** (Argon2id, RFC 9106 §4 second option: t=3, m=64 MiB, p=4). The library deliberately treats fast/balanced/paranoid tiering as **application policy** (the app or the `kdbx` CLI owns its own tiers); pass a hand-built `KDFParameters` to tune. The old `KDFParameters.Profile` + `recommended(_:)` API (and the `Profile`-taking overloads of `makeEmpty` / `upgradeToArgon2id`) remain as `@available(*, deprecated)` shims for source compatibility — kept producing identical parameters, but new code should use `argon2idDefault()` or a hand-built value.

### Lazy read / streaming write (binaries stay on disk)

For vaults where the eager path's "every byte resident from unlock to lock" memory profile is unacceptable (large attachments), use the lazy / streaming pair. See `../SECURITY.md` C-10 for the security framing.

- **`KDBXReader.openMetadataOnly(from:unlockData:maxDecompressedPayloadSize:)`** runs the full decrypt + decompress + inner-header + XML parse, captures per-binary `(offset, length, isProtected, contentHash)` into `[BinaryMetadata]`, then drops the binary bytes. The returned `LazyKDBXContent` keeps the source + unlock key for on-demand re-streaming and is `Sendable` (crosses actor hops the same way `KDBXContent` does). **Peak ≈ the full decompressed payload** (the whole binary pool is materialized before the bytes are dropped), so this does NOT help a memory-capped host — use `openMetadataStreaming` for that.
- **`KDBXReader.openMetadataStreaming(from:unlockData:maxDecompressedPayloadSize:kdfLimits:)`** (4.x only) is the size-independent open. It memory-maps the source (`mappedIfSafe`, so the encrypted bytes are excluded from the Darwin `phys_footprint`), reads the HMAC block stream block-by-block, decrypts + inflates incrementally, and **hashes + discards each binary-pool payload as it streams** — only the XML is retained. Peak ≈ KDF + XML working set, independent of attachment size. Returns the same `LazyKDBXContent` as `openMetadataOnly` (same `binaries` metadata + on-demand bytes). This is the path memory-capped hosts (the iOS AutoFill credential-provider extension, jetsam-limited to ~220 MB) must use — `openMetadataOnly` and eager `parse` both materialize the full pool and get killed mid-parse on vaults with large attachments. 3.x sources throw `unsupportedFormatVersion`.
- **`KDBXReader.streamBinary(from:at:into:)`** re-opens the source (memory-mapped) and replays the decrypt + inflate chain, but a single-binary extractor forwards **only the target attachment** to the sink and discards every other byte, stopping the block loop as soon as the target completes. Peak is the sink's choice (one attachment, page-by-page), independent of vault size; it reuses the stored unlock key + header, so there's no KDF re-run. The sink picks the destination: `DataSink` for unprotected access, `SecureBytesSink` for protected payloads (mlocked + zero-on-deinit, drain via `takeSecureBytes()`), `URLSink` for streaming straight to a destination file URL without ever materializing in `Data`. To resolve MANY binaries at once (rebuilding the pool for a save), use `withDecryptedBinaries(from:_:)` instead — it pays one whole-payload decrypt rather than O(binaries × file).
- **`KDBXSource`** is the input abstraction — `.data(Data)` for tests / in-memory, `.file(URL)` for production. On Apple platforms `.file` reads via `NSFileCoordinator` (read coordinator on every access) to interoperate with iCloud Drive writers; on Linux the file is opened directly. Nesting a `.file` read coordinator inside an outer `NSFileCoordinator` write block on the same URL deadlocks (Apple only) — design write paths to acquire the write coordinator only briefly (e.g. for an atomic temp→destination replace) and run streaming reads outside that scope.
- **`KDBXWriter.streamingWrite(to:content:binaries:unlockData:regenerateSalts:)`** is the streaming counterpart to `write`. Cleartext flows through a chain of `StreamingByteConsumer`s: `GzipStreamWriter` → `EncryptingStreamWriter` → `HMACBlockStreamWriter` → output `FileHandle`. Binaries are pulled one at a time via `[any BinarySource]`. Peak save memory is one attachment plus pipeline working buffers (~64 KB gzip + ≤16 B AES + 1 MB HMAC block), independent of total attachment bytes.
- **`BinarySource`** has two implementations: **`DataBinarySource`** (in-memory bytes, for fresh attachments awaiting their first save) and **`LazyBinarySource`** (re-streams a pool entry from a `LazyKDBXContent` — typical for unchanged attachments during a save where most binaries are still referenced by entries that didn't get edited).
- **Gzip implementation detail**: `Streaming/Zlib.swift` wraps system zlib (`-lz`) directly. The compressor uses `deflateInit2_` with `wBits = 31` (15 + 16 = gzip wrapper, max window) so zlib emits a complete gzip stream itself — no manual header/CRC32 assembly. The decompressor uses `inflateInit2_` with `wBits = 47` (15 + 32 = autodetect gzip/zlib).

### Legacy format (KDBX 3.1) support

KDBXKit reads KDBX 3.1 and migrates it to 4.1 on save. **The writer only ever emits 4.x bytes.** 3.0 is rejected at the version gate with `.unsupportedFormatVersion(3, 0)` (the ArcFour-variant inner stream isn't worth implementing).

- **Read dispatch**: `KDBXReader.parse` peeks the format major version, routes 3.x to `parse3x` in `KDBXReader+Legacy3x.swift`. The 3.x pipeline is a separate file because the framing layer (UInt16 field lengths, `StreamStartBytes` integrity instead of HMAC, hashed block stream, inline XML binary pool) genuinely diverges from 4.x — interleaving them under version branches would force readers to load both specs to follow either path.
- **Synthesis for uniformity**: `Header3xReader` synthesizes `KDFParameters.aes(...)` from the dedicated `TransformSeed` / `TransformRounds` fields, and `parse3x` synthesizes an `InnerHeader` (Salsa20 + `ProtectedStreamKey` + binary pool harvested from `<Meta><Binaries>`) — so downstream code (KDF derivation, keystream, entry-ref resolution) is version-agnostic.
- **Migration signal**: `KDBXContent.legacyFormatNotice` is `.willMigrate(from: .v3_1)` for files opened from 3.x and `nil` otherwise. UI callers pattern-match the enum to present a banner before save; do not parse `parserWarnings` strings.
- **KDF upgrade is opt-in**: `KDBXContent.upgradeToArgon2id(to:)` (defaults to `KDFParameters.argon2idDefault()`; or the general `upgradeKDF(to:)`) swaps the source AES-KDF for Argon2id before save. The library preserves the source KDF by default — apps that want the upgrade (Passie does) call the helper explicitly. The same master password keeps working because the writer derives a new unlock key against the new KDF parameters at save time.
- **Writer clamp is mandatory**: `KDBXWriter.clampingFormatVersionToWritable` upgrades the in-memory `formatVersion` to `.v4_1` before any version-dependent serialization. There's no opt-out — writing 4.x framing under a 3.x version number would yield a file no compliant reader (including ours) could parse.
- **Lazy path is 4.x-only**: `KDBXReader.openMetadataOnly` on a 3.x source throws `.unsupportedFormatVersion(3, _)`. KDBX 3.x stores binaries inline in the (decompressed) XML body, so lazy / re-stream semantics have no analog — callers fall back to eager `parse`, observe `legacyFormatNotice`, and the problem resolves itself on first save.
- **XML dialect**: `XMLDocumentReader.DateFormat` (`.dotNetTicksBase64` default / `.iso8601` for 3.x) picks once at construction. Producers don't mix dialects within a file; no silent fallback between formats — a cross-dialect mismatch throws.
- **CLI**: `kdbx db info` surfaces a legacy-format notice line. `kdbx db migrate <path>` is the explicit migration entry point (default: upgrades KDF to Argon2id at the CLI's `balanced` tier; `--keep-kdf` preserves AES-KDF; no-op on 4.x files). The fast/balanced/paranoid tiers are the CLI's own policy (`KDFProfile` in `KDBXCLICore`), not the library's.

### Format dialects we round-trip

- **Tags separator**: KeePassXC writes `,`-separated, KeePass 2 (.NET) writes `;`. Reader splits on either; writer emits `,` (matches KeePassXC; the KDBX 4.1 XSD nominally says `;` but both clients accept either form). Tag values containing `;` or `,` round-trip lossily.
- **UUIDs on the wire are canonical RFC 4122 bytes**, but `KDFParameters.KDF.AES` and friends store their internal `uuid_t` tuple **byte-reversed**. The `toUInt128().toDataLittleEndian()` chain (writer) and `Data.asUUIDLE()` (reader) compose two reversals into canonical-order on-disk bytes. If you log a deserialised UUID's `.uuidString`, you'll see the byte-reversed form — don't surface that to users.
- **KDBX 4.x dates are Int64 seconds since `0001-01-01T00:00:00Z`, base64-encoded** — NOT 100-ns .NET `DateTime.Ticks`. KDBX 3.x uses ISO 8601 strings. Dialect is selected once per `XMLDocumentReader` (`.dotNetTicksBase64` default / `.iso8601` for 3.x).
- **NullableBoolEx**: writer emits `Null` (title-case); reader accepts both `Null` and `null`. The XSD enumerates both casings.

## Security primitives

- **`SecureBytes`** - page-locked (`mlock`), zero-on-deinit (`memset_s` on Apple/BSD, `explicit_bzero` on Linux), sub-allocated from shared mlock'd arenas (`SecureBytesArena`) so a vault's worth of small protected strings doesn't wire one full page each. Any cleartext key material crossing this module must be `SecureBytes` or scoped through `withRevealedString { ... }` / `withRevealedBytes { ... }`, never `Swift.String`.
- **`ProtectedString.Value`** - access via `.withRevealedString { ... }` or `.bytes`; the old `.stringValue` getter is gone. When designing new APIs that surface protected fields, mirror this pattern - never return a raw `String`.
- **Writer `ProtectedString.Value` -> on-disk mapping (security-critical):** `.regular` writes plaintext XML (`Protected="False"`); `.unprotected` and `.lazyInnerCipher` run the inner-stream cipher and emit `Protected="True"` (encrypted on disk); `.protectedInMemory` emits `ProtectInMemory="True"` with the value **in cleartext on disk** (a not-yet-implemented hint that also raises a parserWarning). For any secret that must be encrypted at rest, use `.unprotected`, NEVER `.protectedInMemory` - the case name is misleading. A reopened encrypted field comes back as `.lazyInnerCipher`.
- **`ConstantTime`** - use for any comparison of secret-derived bytes.
- **`SecureRandom`** - canonical entropy source for salts, IVs, nonces.
- **`KDFParameterLimits`** - caller-injected ceiling on KDF cost (generous `.default` ~1 GiB Argon2 memory; pass a tighter device policy via `parse(..., kdfLimits:)`). Enforced inside `UnlockData.computeUnlockKey` - the single chokepoint every parse path (eager, lazy, 3.x) and both writer paths funnel through - so a new KDF-running path inherits the bound only by going through it. NOT enforced in `parseHeader`, which stays pure so callers can inspect params first. Out-of-policy params throw `KDBXReader.Error.kdfParametersOutOfRange` before any KDF allocates (a DoS defense against KDF-bomb headers).

## CLI (`kdbx`)

Nested subcommand structure (target `kdbx-cli`):
- `db {info, xml, validate, create, rekey, set-cipher, set-compression, set-kdf, empty-recycle-bin, open-bench}` (`open-bench [--lazy|--streaming]` opens a vault under the chosen read path for footprint profiling via `/usr/bin/time -l`; pairs with `scripts/measure-parse.sh`)
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
- **CLI tests that capture stdout/stdin must not use `KDBX_PASSWORD`** - the process-global env var leaks into other (parallel) suites that unlock differently. Feed the password via `--password-stdin`, mark the suite `.serialized` (it mutates global fds), and restore the saved stdout fd BEFORE `readDataToEndOfFile()` (reading first deadlocks). Reference: `PasskeyCommandTests`.

### Interop testing with KeePassXC

- CLI at `/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli`. Gate tests with `FileManager.isExecutableFile(atPath:)` so CI without it no-ops. Suite: `KeePassXCInteropTests`.
- `db-create` and `import` default to KDBX 3.1 - no flag bumps to 4.x. To produce a 4.x fixture, seed from an existing 4.x file (`cp Resources/simple-argon2id-aes256.kdbx target.kdbx`) and mutate, or build via XML and `merge` into a 4.x base.
- Pipe passwords with `(echo "$pw"; echo "$pw") | keepassxc-cli ...`. The password prompt is written to **stdout** - when capturing output, send stderr/stdout to different streams or the prompt ends up in your file.
- Bundled `Resources/kpxc-*.kdbx` fixtures use password `123` unless `KDBXTests.swift` notes otherwise (`kpxc-extras` is `test`).
- **`keepassxc-cli show` only prints the 5 standard fields + tags** - not custom strings, not expiry detail in every locale, not icons. Looks like a missing feature; isn't. The reliable interop pattern for any new field is: write via Passie -> force KeePassXC to re-encrypt by running `add -p <file> /Probe` (stdin gets two passwords: master + new-entry) -> re-open via Passie and assert the field round-tripped. See `PassieKeePassXCInteropTests` for the template.

## Cross-repo coordination

This library is consumed by `Passie/` (the iOS/macOS apps) via `.package(path: "../../KDBXKit")` in `Passie/Modules/Package.swift`. There's no submodule wiring.

- When a change spans both repos (e.g., new `SecureBytes` API consumed by `PassieData`), **land the KDBXKit side first**, then commit the Passie side referencing the new API.
- When designing a new KDBXKit type that the Passie UI layer will surface, expect `PassieData` to add a wrapper (e.g. `VaultUnlock` wraps `UnlockData`) so `PassieUI` doesn't have to `import KDBXKit`. Keep new public types Sendable-clean. Note KDF cost *policy* (the fast/balanced/paranoid tiers and their tuned numbers) lives entirely in the app — `PassieData.VaultCreationParams` owns Passie's tiers; KDBXKit exposes only the single portable `KDFParameters.argon2idDefault()`.

## Platform requirements

- **Swift 6.1+** with strict concurrency enabled.
- **Apple platforms**: macOS 15+, iOS 18+ (declared minima in `Package.swift`).
- **Linux**: any distro with a Swift 6.1 toolchain and `zlib1g-dev` (or equivalent) installed. CI lane uses `swift:6.1-jammy`. Darwin-only APIs (`NSFileCoordinator`, `memset_s`) are gated with `#if canImport(Darwin)`; SecureBytes uses `explicit_bzero` on glibc/musl.
- **No C++ interop required.** The vendored Argon2 is plain C; everything else is pure Swift.

## Type / API gotchas

- `TypedIdentifier<T, V>` constructs via `init(rawValue:)`, e.g. `Vault.Identifier(rawValue: "id")` - there's no `.init()`. `TypedIdentifier` is not `Identifiable`.
- **DocC summary = first paragraph** (up to first blank line). Lead with a complete sentence — `"A buffer that\n\n1. does X"` renders as the fragment `"A buffer that"` in the symbol index.
- **DocC symbol paths**: top-level types (`Header`, `InnerHeader`, `KDFParameters`) live at `/KDBXKit/Type`; nested KDBX types at `/KDBXKit/KDBX/Type`. From a top-level type, cross-reference KDBX-namespaced symbols with the full `` ``KDBX/Entry`` `` form; siblings use just `` ``TypeName`` ``.
- **DocC links to internal/private symbols** emit warnings — use plain backticks (not `` `` ``) for non-public symbols like `Header3xReader`, `parse3x`.
- **Typed throws inside a `rethrows`-over-untyped-closure doesn't propagate.** `SecureBytes.withUnsafeBytes` is `rethrows` over an untyped `throws -> R` — functions that throw from inside it must use untyped `throws`, not `throws(E)`. Catch with bare `catch { … }` and re-wrap at the call site.

## Tooling

- **Trust `swift build` / `swift test` over SourceKit `<new-diagnostics>`.** SourceKit reports phantom "Cannot find X in scope" errors on intra-module references that compile fine. The build is authoritative.
- **SwiftFormat `hoistTry` is disabled in `.swiftformat`.** The rule mangles Swift Testing's `#expect(try X)` into `#expecttry (X)` (lifts `try` out of the macro argument but doesn't add a space). Keep disabled until upstream handles macro calls.
