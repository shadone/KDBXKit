# Changelog

All notable changes to KDBXKit are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-06-11

### Added

- **`KDBXReader.openMetadataStreaming(from:unlockData:...)` — a fully streaming
  metadata-only open.** Unlike `openMetadataOnly`, which decrypts and
  decompresses the whole payload into one buffer before parsing (peak ≈ the
  full decompressed size, attachments included), this reads the HMAC block
  stream one block at a time, decrypts and inflates incrementally (≤64 KiB
  output window), and hashes + discards each binary-pool payload as it streams
  — keeping only the XML. The source is memory-mapped (`mappedIfSafe`), so the
  encrypted bytes are excluded from the Darwin `phys_footprint`. Peak memory is
  then the KDF + XML working set, independent of attachment size. This is the
  path memory-capped hosts (the iOS AutoFill credential-provider extension,
  jetsam-limited to ~220 MB) must use: the eager and `openMetadataOnly` paths
  both materialize the full binary pool and get killed mid-parse on vaults with
  large attachments. 4.x only; 3.x sources throw `unsupportedFormatVersion`.
- **`SecureBytes` now sub-allocates from shared, page-aligned, mlock'd 64 KiB
  arenas** (`SecureBytesArena`) instead of rounding every allocation up to a
  full page and mlock'ing it. A 12-byte secret previously wired a whole 16 KiB
  page; a vault's protected strings could wire hundreds of MB of
  non-reclaimable pages. Secrets still zero on deinit and stay wired, but N
  small secrets now share a handful of pages. Allocations over half an arena
  get their own dedicated region.
- **`kdbx db open-bench [--lazy|--streaming]`** — opens a vault under the chosen
  path for footprint measurement via `/usr/bin/time -l`; plus
  `scripts/measure-parse.sh` for the eager path. A device-free repro harness
  for the AutoFill memory profile.

### Changed

- **`KDBXReader.streamBinary(from:at:into:)` is now size-independent.** It
  previously decrypted + decompressed the whole payload to slice out one
  binary; it now replays the decrypt + inflate chain capturing only the target
  attachment into the sink, discarding every other byte and stopping the block
  loop as soon as the target completes. It reuses the stored unlock key +
  header, so there is no KDF re-run. Byte-identical to the prior behaviour
  across both ciphers and binary sizes spanning the inflate-chunk and HMAC-block
  boundaries.

## [1.2.2] - 2026-05-30

### Changed

- **Streaming AES-256-CBC encrypt now uses CommonCrypto on Apple platforms.**
  The production streaming save path encoded CBC over swift-crypto's
  single-block `AES.permute` (one call + a fresh array per 16-byte block),
  ~78 MB/s — paid on every save. It now runs through a CommonCrypto
  `CCCryptor` (~1 GB/s); a 37 MB payload's AES encrypt drops from ~460 ms to
  ~35 ms. swift-crypto remains the non-Apple fallback. Output is
  byte-identical (StreamingWriteTests + KeePassXC interop).
- **ChaCha20 hot path rewritten for ~8x throughput.** The CryptoSwift-derived
  cipher ran at ~33 MB/s because `process` indexed an `any DataProtocol` per
  byte and `core` re-parsed the key/nonce from existential slices on every
  64-byte block. Key/nonce are now parsed once into little-endian words, the
  keystream is cached per counter, and the XOR loop runs over a contiguous
  buffer; the 20-round core arithmetic is unchanged. A 30 MB ChaCha20 vault
  opens in ~0.2 s, down from ~7.8 s. Pure Swift, so the win applies on every
  platform. Output is byte-identical, validated against the existing project
  KATs, the KeePassXC interop round-trip, and a new authoritative RFC 8439
  §2.4.2 known-answer vector plus a chunking-invariance test.

## [1.2.1] - 2026-05-30

### Changed

- **AES-256-CBC now uses CommonCrypto on Apple platforms.** swift-crypto's
  `_CryptoExtras.AES._CBC` does not engage the CPU AES instructions and runs
  at ~33 MB/s, which dominates the open time of vaults with sizeable
  attachments (a 37 MB AES vault spent ~1100 ms in AES decrypt alone). The
  Apple path now routes through CommonCrypto (AES-NI / ARMv8 crypto
  extensions, ~6 GB/s); measured AES decrypt for that vault dropped from
  ~1100 ms to ~8 ms. swift-crypto remains the fallback on non-Apple
  platforms, so Linux behavior is unchanged. Output is byte-identical and
  verified against the KeePassXC interop round-trip. Affects the eager read,
  lazy read, 3.x legacy read, and eager write; the streaming save path is
  unaffected (it uses a separate per-block cipher).

## [1.2.0] - 2026-05-30

### Added

- **`KDBXReader.withDecryptedBinaries(from:_:)`.** Decrypts a lazy vault's
  payload once and vends a `resolve(index)` closure that slices any binary out
  of the resident buffer (views, no per-binary copy). Use it instead of looping
  `streamBinary` when resolving more than one binary.
- **`LazyBinaryCache`** plus `LazyBinarySource.init(_:at:cache:)`. Pass one
  cache to every `LazyBinarySource` in a streaming write so all sources slice
  from a single decrypt instead of re-decrypting the file per binary.
- **Open-pipeline timing logs.** A `KDBXLog.perf` channel (debug level, quiet by
  default) times each phase of `openMetadataOnly` and the KDF in isolation,
  logging KDF parameters via `KDFParameters.perfSummary`. Surfaces where a slow
  unlock is spent without an Instruments trace.

### Fixed

- **O(binaries × file_size) blowup resolving a lazy vault's binary pool.**
  `streamBinary` re-reads, re-decrypts, and re-decompresses the whole file on
  every call; both save paths looped it once per binary (eager `serializeVault`
  and the streaming writer's `LazyBinarySource`), so a save/serialize of a large
  attachment-heavy vault stalled for minutes — the pool walk runs once per entry
  and once per history snapshot. Both paths now pay a single decrypt regardless
  of attachment count.

## [1.1.0] - 2026-05-28

### Added

- **KDF cost limits.** Caller-injected `KDFParameterLimits` policy, enforced in
  the unlock-key chokepoint (`UnlockData.computeUnlockKey`) across all parse
  paths — eager, lazy, and KDBX 3.x — and both writer paths. New
  `KDBXReader.Error.kdfParametersOutOfRange` rejects KDF-bomb headers before any
  KDF allocates, as a denial-of-service defense. Thread the policy via
  `parse(..., kdfLimits:)`; `parseHeader` stays pure so callers can inspect
  parameters first.
- **Passkeys.** Typed read access for `KPEX_PASSKEY_*` fields with
  KeePassXC-compatible protections, and `kdbx passkey ls` / `kdbx passkey show`
  CLI subcommands. The private key is never printed.
- **Coverage-guided fuzzing.** libFuzzer harnesses for the header, parse, XML,
  variant-dictionary, and block-stream layers, built and run via Docker on Linux
  (macOS toolchains cannot build libFuzzer). Checked-in crashers are replayed as
  a regression gate in `swift test`.
- KDBX compatibility matrix and Docker fuzzing workflow documentation.

### Fixed

- Validate binary references inside entry history snapshots.

## [1.0.0] - 2026-05-20

First stable release.

### Added

- **Library.** Read and write KDBX 4.0 / 4.1 with AES-256-CBC and ChaCha20,
  AES-KDF and Argon2d / Argon2id, gzip compression; eager and streaming/lazy
  read paths. KDBX 3.1 is read-only and migrated to 4.1 on save. KeePassXC
  interop test suite.
- **Security.** `SecureBytes` memory hygiene (mlock + secure-zero),
  `ProtectedString` scoped reveal, constant-time HMAC comparison, end-block HMAC
  verification (closing the truncation-attack window), explicit rejection of
  Argon2 secret-key / associated-data parameters, and XML v2 keyfile hash
  validation.
- **CLI.** `kdbx` tool with `db` / `entry` / `group` / `attach` subcommands,
  including legacy migration, KDF / cipher / compression conversion, and a
  public-header inspection mode (`kdbx db info --public`).
- **Format specification.** `docs/spec/kdbx-container.md` and
  `docs/spec/kdbx-xml.md`, RFC-styled and cross-checked against KeePass.info and
  KeePassXC, including test vectors and the canonical XSD schema.
- **Example.** `Examples/HelloKDBX/` — a minimal vault-reading demo.

[Unreleased]: https://github.com/shadone/KDBXKit/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/shadone/KDBXKit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/shadone/KDBXKit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/shadone/KDBXKit/releases/tag/v1.0.0
