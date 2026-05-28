# Changelog

All notable changes to KDBXKit are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/shadone/KDBXKit/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/shadone/KDBXKit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/shadone/KDBXKit/releases/tag/v1.0.0
