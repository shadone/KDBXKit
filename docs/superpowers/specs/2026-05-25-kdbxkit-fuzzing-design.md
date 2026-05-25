# KDBXKit coverage-guided fuzzing — design

Date: 2026-05-25
Status: approved, pending implementation plan

## Goal

Add coverage-guided (libFuzzer) fuzz targets that feed mutated bytes to
KDBXKit's parsing surfaces and assert a single invariant everywhere:

> **The parser always returns a typed error or a clean result — it never traps
> (force-unwrap, `fatalError`, out-of-bounds), and never hangs.**

This closes the denial-of-service gap a password-format library is expected to
guard against: a hostile `.kdbx` file must not be able to crash or wedge the
host process.

This complements, not replaces, the existing hand-written negative tests
(`MalformedInputTests`, `DecompressionCapTests`, `ValidationTests`). Those pick
specific mutation points; the fuzzer discovers deep paths on its own via
coverage feedback.

## Finding that motivated the KDF work

`KDFParameters.validate()` exists but:

- is **never called** during `KDBXReader.parse` / `parseHeader`, and
- only checks salt length and Argon2 version — it places **no upper bound** on
  Argon2 `memory`, `iterations`, or `parallelism`.

The comment in `Argon2KDF.swift` ("the header validator rejects out-of-range KDF
parameters upstream") is aspirational, not real. A crafted header declaring,
e.g., `memory = 16 GB` passes `parseHeader` and is handed straight to the
vendored C `argon2` on `parse()`, causing OOM or a multi-minute hang. This is a
genuine, currently-open DoS vector and is fixed as part of this work
(section "KDF parameter bound").

## Toolchain constraint

The Apple Xcode Swift toolchain **cannot** build libFuzzer targets:
`-sanitize=fuzzer` is rejected for `*-apple-macosx`, and the fuzzer runtime
(`libclang_rt.fuzzer_osx.a`) is not shipped.

The installed swift.org **`swift-6.1.2-RELEASE`** toolchain
(`~/Library/Developer/Toolchains/`) **does** support it — verified locally with
a 100k-run campaign at ~100k exec/s. The harness pins this toolchain explicitly.

Nothing about the normal Xcode build or `swift test` flow changes. Fuzzing is a
local, on-demand activity driven by a script.

## Components

### 1. Fuzz targets (one executable per surface)

Five thin `executableTarget`s, each compiled `-parse-as-library` and exposing a
single `@_cdecl("LLVMFuzzerTestOneInput")` entry point. The libFuzzer runtime
supplies `main()`.

| Target            | Drives                                   | Import       |
|-------------------|------------------------------------------|--------------|
| `FuzzHeader`      | `KDBXReader.parseHeader(Data)`           | public       |
| `FuzzParse`       | `KDBXReader.parse(_:unlockData:)` (fixed password) | public |
| `FuzzXML`         | inner XML reader on mutated plaintext    | `@testable`  |
| `FuzzVariantDict` | `VariantDictionaryReader`                | `@testable`  |
| `FuzzBlockStream` | `HashedBlockStreamReader`                | `@testable`  |

Each entry point:

1. Wraps the `(pointer, count)` buffer in `Data`.
2. Calls its target API inside a `do { } catch { }` that swallows the target's
   typed error(s) and returns `0`.
3. Returns `0` on clean parse as well.

Any non-typed failure (trap / `fatalError` / OOB / OOM / hang) crashes the
process; libFuzzer captures the offending input as a crasher artifact.

The three inner-layer targets reach parsers that are `internal`, so they use
`@testable import KDBXKit`, which requires the KDBXKit module to be built with
`-enable-testing` (the script passes this).

### 2. Package.swift integration (zero impact on normal builds)

The fuzz targets are added to the package **only when the environment variable
`KDBXKIT_FUZZ=1` is set**, read via `ProcessInfo.processInfo.environment` in
`Package.swift`.

Rationale: the `@testable` targets need `-enable-testing` and would break a
plain `swift build`; gating keeps default `swift build` / `swift test` / Xcode
completely unaffected. The script sets `KDBXKIT_FUZZ=1` before building.

### 3. KDF parameter limits (the DoS fix — lands first)

Make the acceptable KDF cost a **caller-injected policy**, not a hardcoded
constant, and enforce it at the point the KDF actually runs.

**Where enforced:** only at KDF execution — `KDBXReader.parse(_:unlockData:)`
and `UnlockData.computeUnlockKey(kdfParameters:)`. `parseHeader(Data)` is left
pure: it always reads and reports the KDF parameters so a caller can inspect
them and present a tailored message ("this vault needs 2 GB; this device allows
256 MB") *before* attempting an unlock. The DoS only exists when the KDF
allocates/computes, so that is the only boundary that needs the gate.

**API shape:** a value type carrying the ceilings, e.g.

```swift
public struct KDFParameterLimits: Sendable, Equatable {
    public var maxMemory: UInt64          // Argon2 memory, bytes
    public var maxIterations: UInt64      // Argon2 iterations / AES-KDF rounds
    public var maxParallelism: UInt32     // Argon2 lanes
    public static let `default`: KDFParameterLimits  // generous safe ceiling
}
```

Threaded through as a defaulted parameter so existing call sites are unaffected:

```swift
KDBXReader.parse(_ data: Data, unlockData: UnlockData,
                 kdfLimits: KDFParameterLimits = .default) throws(Error) -> KDBXContent
UnlockData.computeUnlockKey(kdfParameters:,
                 limits: KDFParameterLimits = .default) throws(UnlockDataError) -> SecureBytes
```

When parameters exceed `limits`, throw `KDBXReader.Error.kdfParametersOutOfRange`
(carrying which limit was breached and the offending value) before any
allocation or KDF round runs. `computeUnlockKey` surfaces the equivalent through
its own error type.

**Default policy (`.default`):** a generous-but-finite ceiling that real
KeePass/KeePassXC vaults never exceed but absurd DoS values do. Initial values
(revisit in plan/review):

- `maxMemory` = 1 GiB (KeePass defaults are ~64 MiB)
- `maxIterations` — a sane cap covering both Argon2 iterations and AES-KDF
  transform rounds (AES-KDF rounds is a `UInt64`; a huge value is the same DoS
  via CPU instead of memory)
- `maxParallelism` — a sane cap

Existing callers get DoS protection automatically via `.default`. Passie passes
a tighter, device-specific policy (e.g. 256 MiB on iPhone).

**Tests:** a **deterministic** unit test in `KDBXKitTests`: a hand-built header
declaring `memory = 16 GB` must throw `.kdfParametersOutOfRange`, not allocate;
the same header under a permissive custom `KDFParameterLimits` must get past the
limit check (i.e. the policy is actually honored); and an AES-KDF header with an
absurd round count must throw. Per the repo's cross-repo conventions this lands
as its own focused commit ahead of the fuzz tooling.

### 4. Harness-side clamp (speed, not correctness)

`FuzzParse` passes a deliberately tiny `KDFParameterLimits` (memory/iterations
well below `.default`) to `parse`, so any input declaring non-trivial KDF cost
throws `.kdfParametersOutOfRange` immediately instead of running the KDF. This
reuses the same configurable-policy mechanism added in section 3 — no separate
pre-parse or library coupling — and keeps exec/s high. Safety in production
still comes from the library enforcing `.default`, not from this clamp.

### 5. Corpus seeding

- `FuzzHeader` / `FuzzParse`: seeded from the existing golden `.kdbx` fixtures
  in `Tests/KDBXKitTests/Resources/`.
- `FuzzXML` / `FuzzVariantDict` / `FuzzBlockStream`: need plaintext seeds. A
  one-time seed generator (a `@testable` helper invoked by the script) decrypts
  one fixture and dumps the inner XML, a VariantDictionary blob, and a
  hashed-block stream into `Fuzz/corpus/<target>/`.

### 6. `Fuzz/run-fuzz.sh` wrapper

Arguments: target name + duration (and optional pass-through libFuzzer flags).

Responsibilities:

- Select the swift.org `swift-6.1.2-RELEASE` toolchain explicitly.
- Build with `KDBXKIT_FUZZ=1` and
  `-Xswiftc -sanitize=fuzzer -Xswiftc -enable-testing
  -Xcc -fsanitize=fuzzer-no-link` (instruments the vendored C `argon2`/`zlib`
  too) plus `-sanitize=address` for memory-error detection, and the macOS SDK
  sysroot.
- Run the chosen target against `Fuzz/corpus/<target>/`, writing new crashers to
  `Fuzz/crashers/<target>/`, with `-timeout=N` so hangs are caught and
  captured.

### 7. Always-on regression gate

Every crasher found is checked into `Fuzz/crashers/<target>/` and loaded by a
new **deterministic** `FuzzRegressionTests` suite in `KDBXKitTests`, which
asserts each captured input throws cleanly. This runs in plain `swift test` /
CI, so fixed crashers never silently regress even though campaigns are
on-demand.

### 8. Docs

`KDBXKit/Fuzz/README.md`: toolchain requirement, how to run a campaign, how to
triage a crasher and promote it into `FuzzRegressionTests`.

## Out of scope (YAGNI)

- CI integration (nightly or per-PR campaigns). Local, on-demand only for now.
- Dictionary files / structure-aware mutators beyond the seed corpus.
- Fuzzing the writer path.

## Build / commit order

1. KDF parameter bound + its deterministic unit test (library change, own
   commit).
2. Fuzz targets, `Package.swift` gating, seed generator, `run-fuzz.sh`,
   `Fuzz/README.md`.
3. `FuzzRegressionTests` scaffold (loads from `Fuzz/crashers/`, initially empty
   or with any crashers found during bring-up).
