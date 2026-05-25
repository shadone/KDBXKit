<!--
Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>

SPDX-License-Identifier: BSD-2-Clause
-->

# KDBXKit Fuzzing

Coverage-guided (libFuzzer) fuzz targets over KDBXKit's parsing surfaces. Each
target asserts one invariant everywhere: the parser returns a typed error or a
clean result — it never traps and never hangs.

## Why Docker

The Xcode Swift toolchain cannot build libFuzzer targets at all (`-sanitize=fuzzer`
is unsupported and the fuzzer runtime is absent). Getting SwiftPM to link a
libFuzzer executable on the swift.org macOS toolchain required fragile workarounds
(C entry-point stubs, dlsym, release-only flags, custom linker invocations). On
Linux the libFuzzer runtime supplies `main` cleanly, so the harness builds and runs
in a container without any of that ceremony. Prerequisite: Docker running.

The base image is `swift:6.1-jammy` (Swift 6.1.3), pinned to match the CI Linux
lane used by `scripts/test-linux.sh`.

## Running a campaign

```
Fuzz/run-fuzz.sh <header|parse|xml|variantdict|blockstream> [seconds]
```

Default duration is **60 seconds**. The repo is bind-mounted into the container;
`Fuzz/corpus/<target>/` is read and grown in place, and any crasher is written to
`Fuzz/crashers/<target>/`.

### Target table

| Key | Surface fuzzed |
|---|---|
| `header` | `KDBXReader.parseHeader` — outer binary header only, no credentials |
| `parse` | Full `KDBXReader.parse` pipeline (header + KDF + decryption + XML) |
| `xml` | Post-decryption XML reader |
| `variantdict` | Header `VariantDictionary` reader |
| `blockstream` | KDBX 3.x hashed-block stream decoder |

The fuzz targets are compiled only when `KDBXKIT_FUZZ=1` is set. A normal
`swift build`, `swift test`, or Xcode build never sees them.

## Corpora and seeds

`Fuzz/corpus/<target>/` is the input corpus for that target; libFuzzer reads it at
startup and writes new interesting inputs back into the same directory as the
campaign runs.

`Fuzz/crashers/<target>/` holds captured crasher inputs. **Check these in** —
`FuzzRegressionTests` (in `Tests/KDBXKitTests/FuzzRegressionTests.swift`) replays
every checked-in crasher during `swift test` and asserts they stay fixed.

### How each corpus is seeded

- **`header` and `parse`** — `run-fuzz.sh` auto-seeds the corpus (idempotently,
  with `cp -n`) from all `*.kdbx` fixtures under `Tests/KDBXKitTests/Resources/`
  before starting the container. No manual step required.

- **`xml`** — ships a committed seed (`Fuzz/corpus/xml/seed-fixture.xml`) produced
  by `FuzzSeedGen`. To regenerate it:

  ```
  KDBXKIT_FUZZ=1 swift run FuzzSeedGen \
      Tests/KDBXKitTests/Resources/simple-argon2id-aes256.kdbx \
      123 \
      Fuzz/corpus
  ```

  `FuzzSeedGen` unlocks the fixture with the given password, retains the decrypted
  XML document, and writes it to `<corpus-root>/xml/seed-fixture.xml`. A real,
  structurally-valid XML body gives the fuzzer a far richer starting point than an
  empty corpus.

- **`variantdict` and `blockstream`** — start from an empty corpus; libFuzzer
  populates them through discovery.

## Triaging a crasher

When libFuzzer finds an input that causes a trap or hang it writes the offending
bytes to `Fuzz/crashers/<target>/crash-<hash>` (or `timeout-*`, `leak-*`,
`oom-*`). To reproduce, re-run the same target and pass the crasher file as the
sole positional argument.

Fix the parser so it throws a typed error instead of trapping on that input. Then
**keep the crasher file checked in** under `Fuzz/crashers/<target>/`. The
`FuzzRegressionTests` suite in `Tests/KDBXKitTests/FuzzRegressionTests.swift` runs
every checked-in crasher as part of `swift test`, asserting that each one stays
fixed.

## KDF denial-of-service note

KDF cost is bounded by `KDFParameterLimits`, enforced in
`UnlockData.computeUnlockKey` (the `.default` limit caps Argon2 memory at roughly
1 GiB). The `parse` fuzz target passes a deliberately tiny `KDFParameterLimits`
(1 MiB Argon2 memory, 2 iterations, 10 000 AES-KDF rounds) so any input declaring
real KDF cost throws `kdfParametersOutOfRange` immediately, and the engine spends
its time exploring the parser rather than burning time in the KDF. Production safety
comes from the library's `.default` limits, not from this clamp.
