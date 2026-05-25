# KDBXKit Coverage-Guided Fuzzing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add libFuzzer fuzz targets over KDBXKit's parsing surfaces that assert "typed throw or clean result — never trap, never hang," and close the KDF-bomb DoS vector by making KDF cost a caller-injected, default-enforced policy.

**Architecture:** First a library change — a `KDFParameterLimits` value type enforced inside `UnlockData.computeUnlockKey` (the single choke point all parse paths funnel through), threaded through the public parse entry points with a generous `.default`. Then a set of thin `@_cdecl("LLVMFuzzerTestOneInput")` executables gated behind `KDBXKIT_FUZZ=1` in `Package.swift`, driven by a shell wrapper that pins the swift.org toolchain (the Xcode toolchain can't build libFuzzer). Crashers are checked in and replayed by a deterministic regression suite that runs in normal `swift test`.

**Tech Stack:** Swift 6.1 (swift.org `swift-6.1.2-RELEASE` toolchain for fuzzing only), SwiftPM, swift-testing, libFuzzer (`-sanitize=fuzzer`), AddressSanitizer.

---

## BUILD APPROACH UPDATE (2026-05-26): Linux/Docker, not macOS

During implementation, building the libFuzzer targets on macOS proved too fragile (SwiftPM `executableTarget` + `-parse-as-library` doesn't emit the `main` symbol libFuzzer needs, requiring a C stub + `dlsym` + release-only + an Apple-`ld` workaround). **Decision: build and run the fuzzers in a Linux container** where plain `-sanitize=fuzzer` is well-trodden. The harness `main.swift` files (Tasks 6, 7) are portable and unchanged. Only Task 9 (was: swift.org-toolchain `run-fuzz.sh`) and Task 11 (README) change to Docker, and Tasks 6/7/8 are verified inside the container. The regression suite (Task 10) still runs in normal macOS `swift test`.

## Reference: verified facts

- libFuzzer is NOT cleanly buildable on macOS (see update above). Fuzzing happens in Docker on Linux.
- `KDBXReader.parse(_:unlockData:)` (static, `KDBXReader.swift:160`) and the mutating `parse(unlockData:retainsXMLForDiagnostics:maxDecompressedPayloadSize:)` (`:228`) and `parseHeader(_:)` (`:168`).
- `UnlockData.computeUnlockKey(kdfParameters:)` (`UnlockData.swift:153`, `throws(UnlockDataError)`) is called by the eager path (`KDBXReader.swift:300`), the lazy path (`KDBXReader+Lazy.swift:222`), and the 3.x path (`KDBXReader+Legacy3x.swift:84`).
- `KDBXReader.Error` enum at `KDBXReader.swift:29`; `UnlockDataError` at `UnlockData.swift:28` with cases `unsupportedKDF(UUID)`, `kdfFailed(reason:)`, `unsupportedKDFParameter(name:)`.
- `KDFParameters` (`Header/KDFParameters.swift`): `.aes(AES, additional:)` where `AES.rounds: UInt64`; `.argon2d`/`.argon2id(Argon2, additional:)` where `Argon2` has `iterations: UInt64`, `memory: UInt64` (bytes), `parallelism: UInt32`; `.unknown(uuid:)`.
- Inner parsers (all `internal`, need `@testable`): `XMLDocumentReader(xmlDocument: String, keystreamSource: KeystreamSource, dateFormat:) throws(Error)` then `.parse() throws(Error) -> KDBX` (`Database/XMLDocumentReader.swift:358`); `VariantDictionaryReader(data: Data).parse() throws(Error) -> VariantDictionary` (`Header/VariantDictionaryReader.swift:65`); `HashedBlockStreamReader.decode(_ data: Data) throws(Error) -> Data` (static, `Streaming/HashedBlockStreamReader.swift:49`).
- `KeystreamSource(algorithm: .chacha20, key: SecureBytes, nonce: Data)` is public (`InnerHeader/KeystreamSource.swift:43`). `SecureBytes(_ data: Data)` init is used in tests.
- Golden fixtures live in `Tests/KDBXKitTests/Resources/*.kdbx`. `Examples/HelloKDBX/demo.kdbx` also exists.

## Design note refining the spec

The spec said "a sane cap covering both Argon2 iterations and AES-KDF transform rounds." On reflection these have different cost models (Argon2 iterations multiply memory passes; AES-KDF rounds are pure CPU and legitimately run to tens of millions), so a single shared cap would either reject real AES-KDF files or leave Argon2 iteration DoS open. This plan splits them into `maxArgon2Iterations` and `maxAESKDFRounds`.

## File structure

- Create `Sources/KDBXKit/KDF/KDFParameterLimits.swift` — the policy value type + breach check.
- Modify `Sources/KDBXKit/UnlockData.swift` — add `UnlockDataError.kdfParametersOutOfRange`, add `limits:` param to `computeUnlockKey`, enforce.
- Modify `Sources/KDBXKit/KDBXReader.swift` — add `KDBXReader.Error.kdfParametersOutOfRange`, add `kdfLimits:` to both `parse` overloads, map the unlock error, pass to `parse3x`.
- Modify `Sources/KDBXKit/KDBXReader+Legacy3x.swift` and `KDBXReader+Lazy.swift` — thread `kdfLimits` to `computeUnlockKey`.
- Create `Tests/KDBXKitTests/KDFParameterLimitsTests.swift` — deterministic limit tests.
- Modify `Package.swift` — add `KDBXKIT_FUZZ`-gated fuzz + seed targets.
- Create `Fuzz/Sources/FuzzHeader/main.swift`, `FuzzParse/main.swift`, `FuzzXML/main.swift`, `FuzzVariantDict/main.swift`, `FuzzBlockStream/main.swift`, `FuzzSeedGen/main.swift`.
- Create `Fuzz/run-fuzz.sh`, `Fuzz/README.md`, `Fuzz/corpus/<target>/.gitkeep`, `Fuzz/crashers/<target>/.gitkeep`.
- Create `Tests/KDBXKitTests/FuzzRegressionTests.swift` — replays checked-in crashers.

---

## Task 1: `KDFParameterLimits` value type + breach check

**Files:**
- Create: `Sources/KDBXKit/KDF/KDFParameterLimits.swift`
- Test: `Tests/KDBXKitTests/KDFParameterLimitsTests.swift`

- [ ] **Step 1: Write the failing test**

Create `Tests/KDBXKitTests/KDFParameterLimitsTests.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDFParameterLimits — caller-injected KDF cost policy")
struct KDFParameterLimitsTests {
    private func argon2id(memory: UInt64, iterations: UInt64 = 1, parallelism: UInt32 = 1) -> KDFParameters {
        .argon2id(
            .init(version: .v1_3, salt: Data(repeating: 0, count: 32), iterations: iterations, memory: memory, parallelism: parallelism),
            additional: [:]
        )
    }

    @Test("default policy admits a normal vault (64 MiB Argon2)")
    func defaultAdmitsNormal() {
        #expect(KDFParameterLimits.default.breach(for: argon2id(memory: 64 * 1024 * 1024)) == nil)
    }

    @Test("default policy rejects a 16 GB memory bomb")
    func defaultRejectsMemoryBomb() {
        #expect(KDFParameterLimits.default.breach(for: argon2id(memory: 16 * 1024 * 1024 * 1024)) != nil)
    }

    @Test("a permissive custom policy admits the same large value")
    func permissivePolicyAdmits() {
        let permissive = KDFParameterLimits(
            maxArgon2Memory: 32 * 1024 * 1024 * 1024,
            maxArgon2Iterations: 1_000,
            maxArgon2Parallelism: 1_024,
            maxAESKDFRounds: 1_000_000_000
        )
        #expect(permissive.breach(for: argon2id(memory: 16 * 1024 * 1024 * 1024)) == nil)
    }

    @Test("AES-KDF round bomb is rejected by default")
    func defaultRejectsAESRoundBomb() {
        let params = KDFParameters.aes(.init(salt: Data(repeating: 0, count: 32), rounds: .max), additional: [:])
        #expect(KDFParameterLimits.default.breach(for: params) != nil)
    }

    @Test("unknown KDF is not flagged by the limit check")
    func unknownKDFNotFlagged() {
        #expect(KDFParameterLimits.default.breach(for: .unknown(uuid: UUID())) == nil)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --filter KDFParameterLimitsTests`
Expected: FAIL — `cannot find 'KDFParameterLimits' in scope`.

- [ ] **Step 3: Write the implementation**

Create `Sources/KDBXKit/KDF/KDFParameterLimits.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Caller-injected upper bounds on KDF cost. The KDF parameters in a KDBX
/// header are attacker-controlled; without a bound a crafted file can declare
/// multi-gigabyte Argon2 memory or billions of iterations and wedge or OOM the
/// host the moment an unlock is attempted. Callers pass the policy acceptable
/// for their device (e.g. a tighter memory ceiling on iPhone); ``default``
/// applies a generous-but-finite ceiling that real KeePass/KeePassXC vaults
/// never exceed.
///
/// Enforced at KDF execution only (``UnlockData/computeUnlockKey(kdfParameters:limits:)``
/// and the `KDBXReader.parse` paths), never in ``KDBXReader/parseHeader(_:)`` —
/// header inspection stays pure so a caller can read the parameters and warn
/// the user before attempting an expensive unlock.
public struct KDFParameterLimits: Sendable, Equatable {
    /// Maximum Argon2 memory cost, in bytes.
    public var maxArgon2Memory: UInt64
    /// Maximum Argon2 iteration (time) cost.
    public var maxArgon2Iterations: UInt64
    /// Maximum Argon2 parallelism (lanes).
    public var maxArgon2Parallelism: UInt32
    /// Maximum AES-KDF transform rounds. Pure CPU, so the ceiling is higher
    /// than the Argon2 iteration cap.
    public var maxAESKDFRounds: UInt64

    public init(
        maxArgon2Memory: UInt64,
        maxArgon2Iterations: UInt64,
        maxArgon2Parallelism: UInt32,
        maxAESKDFRounds: UInt64
    ) {
        self.maxArgon2Memory = maxArgon2Memory
        self.maxArgon2Iterations = maxArgon2Iterations
        self.maxArgon2Parallelism = maxArgon2Parallelism
        self.maxAESKDFRounds = maxAESKDFRounds
    }

    /// Generous defaults: real vaults sit far below these, absurd DoS values
    /// sit far above. KeePass Argon2 defaults are ~64 MiB / a few iterations.
    public static let `default` = KDFParameterLimits(
        maxArgon2Memory: 1 << 30,          // 1 GiB
        maxArgon2Iterations: 1_000,
        maxArgon2Parallelism: 1 << 10,     // 1024 lanes
        maxAESKDFRounds: 100_000_000       // completes in a few seconds
    )

    /// Returns a human-readable reason when `params` exceed these limits, or
    /// `nil` when they are within policy. `.unknown` KDFs are not flagged here —
    /// they fail later as `unsupportedKDF`.
    public func breach(for params: KDFParameters) -> String? {
        switch params {
        case let .aes(p, _):
            if p.rounds > maxAESKDFRounds {
                return "AES-KDF rounds \(p.rounds) exceeds limit \(maxAESKDFRounds)"
            }
        case let .argon2d(p, _), let .argon2id(p, _):
            if p.memory > maxArgon2Memory {
                return "Argon2 memory \(p.memory) exceeds limit \(maxArgon2Memory)"
            }
            if p.iterations > maxArgon2Iterations {
                return "Argon2 iterations \(p.iterations) exceeds limit \(maxArgon2Iterations)"
            }
            if p.parallelism > maxArgon2Parallelism {
                return "Argon2 parallelism \(p.parallelism) exceeds limit \(maxArgon2Parallelism)"
            }
        case .unknown:
            break
        }
        return nil
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `swift test --filter KDFParameterLimitsTests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add Sources/KDBXKit/KDF/KDFParameterLimits.swift Tests/KDBXKitTests/KDFParameterLimitsTests.swift
git commit -m "feat: add KDFParameterLimits policy type with breach check"
```

---

## Task 2: Enforce limits in `computeUnlockKey`

**Files:**
- Modify: `Sources/KDBXKit/UnlockData.swift:28` (error enum) and `:153` (method)
- Test: `Tests/KDBXKitTests/KDFParameterLimitsTests.swift` (extend)

- [ ] **Step 1: Write the failing test**

Append to the `KDFParameterLimitsTests` suite in `Tests/KDBXKitTests/KDFParameterLimitsTests.swift`:

```swift
    @Test("computeUnlockKey rejects out-of-policy params before running the KDF")
    func computeUnlockKeyEnforces() throws {
        let unlock = UnlockData(masterPassword: "test")
        let bomb = argon2id(memory: 16 * 1024 * 1024 * 1024)
        do {
            _ = try unlock.computeUnlockKey(kdfParameters: bomb, limits: .default)
            Issue.record("Expected kdfParametersOutOfRange")
        } catch let error {
            #expect(error == .kdfParametersOutOfRange(reason: error.reasonForOutOfRange ?? ""))
        }
    }

    @Test("computeUnlockKey runs the KDF when params are within policy")
    func computeUnlockKeyProceeds() throws {
        let unlock = UnlockData(masterPassword: "test")
        // 8 MiB / 1 iteration is within .default and fast to compute.
        let small = argon2id(memory: 8 * 1024 * 1024, iterations: 1, parallelism: 1)
        let key = try unlock.computeUnlockKey(kdfParameters: small, limits: .default)
        #expect(key.count == 32)
    }
```

Add this helper extension at the bottom of the file (outside the suite) so the equality assertion above can extract the reason:

```swift
private extension UnlockDataError {
    var reasonForOutOfRange: String? {
        if case let .kdfParametersOutOfRange(reason) = self { return reason }
        return nil
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --filter KDFParameterLimitsTests`
Expected: FAIL — `computeUnlockKey` has no `limits:` parameter; `kdfParametersOutOfRange` is not a case of `UnlockDataError`.

- [ ] **Step 3: Add the error case**

In `Sources/KDBXKit/UnlockData.swift`, add to the `UnlockDataError` enum (around `:49`, after `unsupportedKDFParameter`):

```swift
    /// The KDF parameters in the header exceed the caller's
    /// ``KDFParameterLimits`` policy. Thrown before any KDF allocation/compute,
    /// closing the denial-of-service vector where a crafted file declares an
    /// absurd Argon2 memory or iteration cost.
    case kdfParametersOutOfRange(reason: String)
```

- [ ] **Step 4: Enforce in the method**

In `Sources/KDBXKit/UnlockData.swift`, change the signature at `:153` and add the check as the first statement:

```swift
    public func computeUnlockKey(
        kdfParameters: KDFParameters,
        limits: KDFParameterLimits = .default
    ) throws(UnlockDataError) -> SecureBytes {
        if let reason = limits.breach(for: kdfParameters) {
            throw .kdfParametersOutOfRange(reason: reason)
        }
        switch kdfParameters {
```

(Leave the rest of the `switch` body unchanged.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `swift test --filter KDFParameterLimitsTests`
Expected: PASS (7 tests).

- [ ] **Step 6: Commit**

```bash
git add Sources/KDBXKit/UnlockData.swift Tests/KDBXKitTests/KDFParameterLimitsTests.swift
git commit -m "feat: enforce KDFParameterLimits in computeUnlockKey"
```

---

## Task 3: Add `KDBXReader.Error.kdfParametersOutOfRange` and map it

**Files:**
- Modify: `Sources/KDBXKit/KDBXReader.swift:29` (error enum), `:300` and `KDBXReader+Lazy.swift:222`, `KDBXReader+Legacy3x.swift:84` (the `computeUnlockKey` catch blocks)

- [ ] **Step 1: Add the error case**

In `Sources/KDBXKit/KDBXReader.swift`, add to the `KDBXReader.Error` enum (in the `// MARK: - Corruption` area, after `corruptedHeader`):

```swift
        /// The header's KDF parameters exceed the limits the caller passed via
        /// `kdfLimits` (defaulting to ``KDFParameterLimits/default``). Surfaced
        /// before any KDF runs — a defense against KDF-bomb denial of service.
        case kdfParametersOutOfRange(reason: String)
```

- [ ] **Step 2: Map the unlock error at each call site**

In all three files, the `computeUnlockKey` call is wrapped in `do throws(UnlockDataError) { ... } catch { switch error { ... } }`. Add this case to each `switch error` (alongside the existing `.unsupportedKDF` / `.kdfFailed` / `.unsupportedKDFParameter` cases):

`Sources/KDBXKit/KDBXReader.swift` (~`:300`), `Sources/KDBXKit/KDBXReader+Lazy.swift` (~`:222`), `Sources/KDBXKit/KDBXReader+Legacy3x.swift` (~`:84`):

```swift
            case let .kdfParametersOutOfRange(reason):
                throw .kdfParametersOutOfRange(reason: reason)
```

- [ ] **Step 3: Build to verify the switches are exhaustive**

Run: `swift build`
Expected: builds cleanly. If any `switch error` over `UnlockDataError` is now non-exhaustive, the compiler names the file — add the case there too.

- [ ] **Step 4: Commit**

```bash
git add Sources/KDBXKit/KDBXReader.swift Sources/KDBXKit/KDBXReader+Lazy.swift Sources/KDBXKit/KDBXReader+Legacy3x.swift
git commit -m "feat: surface kdfParametersOutOfRange from KDBXReader"
```

---

## Task 4: Thread `kdfLimits` through the public parse entry points

**Files:**
- Modify: `Sources/KDBXKit/KDBXReader.swift:160` (static parse), `:228` (mutating parse), `KDBXReader+Legacy3x.swift:37` (parse3x), `KDBXReader+Lazy.swift:45` & related lazy entry points
- Test: `Tests/KDBXKitTests/KDFParameterLimitsTests.swift` (extend)

- [ ] **Step 1: Write the failing test**

Append to the `KDFParameterLimitsTests` suite. This uses a real fixture and a deliberately tiny limit to force a rejection without crafting a 16 GB header:

```swift
    @Test("parse() honors a tiny caller policy and rejects a real fixture's KDF")
    func parseHonorsTinyPolicy() throws {
        let url = try #require(Bundle.module.url(forResource: "simple-argon2id-aes256", withExtension: "kdbx"))
        let data = try Data(contentsOf: url)
        let tiny = KDFParameterLimits(
            maxArgon2Memory: 1024,          // 1 KiB — below any real vault
            maxArgon2Iterations: 1,
            maxArgon2Parallelism: 1,
            maxAESKDFRounds: 1
        )
        #expect(throws: KDBXReader.Error.self) {
            _ = try KDBXReader.parse(data, unlockData: UnlockData(masterPassword: "wrong"), kdfLimits: tiny)
        }
    }
```

(The fixture's real password is unknown here, but the limit check runs before credential verification, so it throws `.kdfParametersOutOfRange` regardless of the password.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `swift test --filter parseHonorsTinyPolicy`
Expected: FAIL — `parse` has no `kdfLimits:` argument.

- [ ] **Step 3: Add `kdfLimits` to the static `parse`**

`Sources/KDBXKit/KDBXReader.swift:160`:

```swift
    public static func parse(
        _ data: Data,
        unlockData: UnlockData,
        kdfLimits: KDFParameterLimits = .default
    ) throws(Error) -> KDBXContent {
        var reader = KDBXReader(data)
        return try reader.parse(unlockData: unlockData, kdfLimits: kdfLimits)
    }
```

- [ ] **Step 4: Add `kdfLimits` to the mutating `parse` and pass it down**

`Sources/KDBXKit/KDBXReader.swift:228` — add the parameter to the signature:

```swift
    public mutating func parse(
        unlockData: UnlockData?,
        retainsXMLForDiagnostics: Bool = false,
        maxDecompressedPayloadSize: Int = KDBXReader.maxDecompressedPayloadSize,
        kdfLimits: KDFParameterLimits = .default
    ) throws(Error) -> KDBXContent {
```

In the same method, pass it to the `parse3x` call (~`:240`):

```swift
            return try parse3x(
                unlockData: unlockData,
                retainsXMLForDiagnostics: retainsXMLForDiagnostics,
                maxDecompressedPayloadSize: maxDecompressedPayloadSize,
                kdfLimits: kdfLimits
            )
```

And at the `computeUnlockKey` call (~`:300`):

```swift
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: header.kdfParameters, limits: kdfLimits)
```

- [ ] **Step 5: Add `kdfLimits` to `parse3x`**

`Sources/KDBXKit/KDBXReader+Legacy3x.swift:37` — add `kdfLimits: KDFParameterLimits` to the signature (no default; it is always called internally with the value). Then at the `computeUnlockKey` call (~`:84`):

```swift
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: header.kdfParameters, limits: kdfLimits)
```

- [ ] **Step 6: Thread `kdfLimits` through the lazy entry points**

In `Sources/KDBXKit/KDBXReader+Lazy.swift`, add `kdfLimits: KDFParameterLimits = .default` to each **public** lazy entry point signature (the ones with `maxDecompressedPayloadSize` defaulted, ~`:45`), and forward it through the internal helpers (~`:184`, `:258`, `:296` take it as a non-defaulted `Int` alongside `maxDecompressedPayloadSize`; add `kdfLimits: KDFParameterLimits` there too). At the `computeUnlockKey` call (~`:222`):

```swift
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: header.kdfParameters, limits: kdfLimits)
```

- [ ] **Step 7: Build and run the full suite**

Run: `swift build && swift test --filter KDFParameterLimitsTests`
Expected: builds; PASS (8 tests). If the build flags a lazy helper missing `kdfLimits`, add the parameter to that helper and forward it.

- [ ] **Step 8: Run the whole test suite for regressions**

Run: `swift test`
Expected: all existing tests still PASS — `.default` admits every golden fixture.

- [ ] **Step 9: Commit**

```bash
git add Sources/KDBXKit/KDBXReader.swift Sources/KDBXKit/KDBXReader+Legacy3x.swift Sources/KDBXKit/KDBXReader+Lazy.swift Tests/KDBXKitTests/KDFParameterLimitsTests.swift
git commit -m "feat: thread kdfLimits through all KDBXReader parse paths"
```

---

## Task 5: Gate fuzz targets in Package.swift + scaffold the Fuzz directory

**Files:**
- Modify: `Package.swift`
- Create: `Fuzz/corpus/{header,parse,xml,variantdict,blockstream}/.gitkeep`, `Fuzz/crashers/{header,parse,xml,variantdict,blockstream}/.gitkeep`

- [ ] **Step 1: Create the corpus/crasher directory skeleton**

Run:

```bash
cd /Users/denis/dev/info.ddenis/PasswordManager/KDBXKit
for t in header parse xml variantdict blockstream; do
  mkdir -p "Fuzz/corpus/$t" "Fuzz/crashers/$t"
  touch "Fuzz/corpus/$t/.gitkeep" "Fuzz/crashers/$t/.gitkeep"
done
```

- [ ] **Step 2: Add the gated targets to Package.swift**

At the top of `Package.swift`, after `import PackageDescription`, add:

```swift
import Foundation
```

Locate the `let package = Package(...)` and its `targets: [ ... ]` array. Refactor so the targets array is built in a `var`, then conditionally extended. Immediately before `let package = Package(`:

```swift
let fuzzSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .unsafeFlags(["-parse-as-library"]),
]

var fuzzTargets: [Target] = []
if ProcessInfo.processInfo.environment["KDBXKIT_FUZZ"] == "1" {
    fuzzTargets = [
        .executableTarget(name: "FuzzHeader", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzHeader", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzParse", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzParse", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzXML", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzXML", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzVariantDict", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzVariantDict", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzBlockStream", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzBlockStream", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzSeedGen", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzSeedGen", swiftSettings: [.swiftLanguageMode(.v6)]),
    ]
}
```

Then in the `Package(...)` call, change the `targets:` argument from a literal array to that literal **plus** `fuzzTargets`. If the existing form is `targets: [ <existing> ]`, change it to:

```swift
    targets: [ <existing, unchanged> ] + fuzzTargets
```

- [ ] **Step 3: Verify normal build is unaffected**

Run: `swift build`
Expected: builds; the fuzz targets are absent (no `KDBXKIT_FUZZ`). `swift test` still green.

- [ ] **Step 4: Verify the gate turns targets on**

Run: `KDBXKIT_FUZZ=1 swift package describe --type json | grep -c FuzzHeader`
Expected: `1` (the target is now declared). It won't *build* with the Xcode toolchain — that's Task 9's job — this only confirms the gate wiring.

- [ ] **Step 5: Commit**

```bash
git add Package.swift Fuzz/corpus Fuzz/crashers
git commit -m "build: gate libFuzzer targets behind KDBXKIT_FUZZ env"
```

---

## Task 6: Public-surface fuzz harnesses (FuzzHeader, FuzzParse)

**Files:**
- Create: `Fuzz/Sources/FuzzHeader/main.swift`, `Fuzz/Sources/FuzzParse/main.swift`

- [ ] **Step 1: Write FuzzHeader**

Create `Fuzz/Sources/FuzzHeader/main.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for KDBXReader.parseHeader. Asserts the header parser
// returns a typed error or a Header — never a trap, never a hang. A trap
// (force-unwrap / fatalError / OOB) crashes the process and libFuzzer captures
// the input; a typed throw is swallowed by `try?`.

import Foundation
import KDBXKit

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    _ = try? KDBXReader.parseHeader(data)
    return 0
}
```

- [ ] **Step 2: Write FuzzParse**

Create `Fuzz/Sources/FuzzParse/main.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the full KDBXReader.parse pipeline. A deliberately
// tiny KDFParameterLimits makes any input declaring real KDF cost throw
// kdfParametersOutOfRange immediately, so the engine spends its time in the
// parser rather than the KDF. Safety in production comes from the library's
// .default limits, not from this clamp.

import Foundation
import KDBXKit

private let unlock = UnlockData(masterPassword: "fuzz")
private let tinyLimits = KDFParameterLimits(
    maxArgon2Memory: 1 << 20,   // 1 MiB
    maxArgon2Iterations: 2,
    maxArgon2Parallelism: 2,
    maxAESKDFRounds: 10_000
)

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    _ = try? KDBXReader.parse(data, unlockData: unlock, kdfLimits: tinyLimits)
    return 0
}
```

- [ ] **Step 3: Verify the sources compile under the gate (parse only, no fuzzer link)**

Run: `KDBXKIT_FUZZ=1 swift build --target FuzzHeader -Xswiftc -parse-as-library 2>&1 | tail -5`
Expected: may fail at the *link* step (no fuzzer runtime in the Xcode toolchain) but must show no Swift *compile* errors in `main.swift`. Compile errors must be fixed here; a link error referencing `LLVMFuzzerTestOneInput`/`_main` is expected and fine.

- [ ] **Step 4: Commit**

```bash
git add Fuzz/Sources/FuzzHeader Fuzz/Sources/FuzzParse
git commit -m "test: add FuzzHeader and FuzzParse libFuzzer harnesses"
```

---

## Task 7: Inner-layer fuzz harnesses (FuzzXML, FuzzVariantDict, FuzzBlockStream)

**Files:**
- Create: `Fuzz/Sources/FuzzXML/main.swift`, `Fuzz/Sources/FuzzVariantDict/main.swift`, `Fuzz/Sources/FuzzBlockStream/main.swift`

- [ ] **Step 1: Write FuzzXML**

Create `Fuzz/Sources/FuzzXML/main.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the post-decryption XML reader. Bypasses HMAC so
// the engine actually reaches XMLDocumentReader. A fixed keystream is fine —
// the reader only uses it to decrypt protected fields, and gibberish plaintext
// must not crash it.

import Foundation
@testable import KDBXKit

private let keystream = KeystreamSource(
    algorithm: .chacha20,
    key: SecureBytes(Data(repeating: 0, count: 32)),
    nonce: Data(repeating: 0, count: 12)
)

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    guard let xml = String(data: data, encoding: .utf8) else { return 0 }
    let reader = try? XMLDocumentReader(xmlDocument: xml, keystreamSource: keystream)
    _ = try? reader?.parse()
    return 0
}
```

- [ ] **Step 2: Write FuzzVariantDict**

Create `Fuzz/Sources/FuzzVariantDict/main.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the header VariantDictionary reader.

import Foundation
@testable import KDBXKit

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    var reader = VariantDictionaryReader(data: data)
    _ = try? reader.parse()
    return 0
}
```

(If the compiler reports `parse()` is non-mutating, change `var reader` to `let reader`.)

- [ ] **Step 3: Write FuzzBlockStream**

Create `Fuzz/Sources/FuzzBlockStream/main.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// libFuzzer entry point for the KDBX 3.x hashed-block stream decoder.

import Foundation
@testable import KDBXKit

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    guard let start else { return 0 }
    let data = Data(bytes: start, count: count)
    _ = try? HashedBlockStreamReader.decode(data)
    return 0
}
```

- [ ] **Step 4: Verify compilation under the gate**

Run: `KDBXKIT_FUZZ=1 swift build --target FuzzVariantDict -Xswiftc -parse-as-library 2>&1 | tail -8`
Expected: no Swift compile errors (link error is fine). Repeat for `FuzzXML` and `FuzzBlockStream`. Fix any compile error — most likely a non-mutating `parse()` (Step 2 note) or a `SecureBytes`/`KeystreamSource` initializer mismatch (cross-check against `KeystreamSourceTests.swift`).

- [ ] **Step 5: Commit**

```bash
git add Fuzz/Sources/FuzzXML Fuzz/Sources/FuzzVariantDict Fuzz/Sources/FuzzBlockStream
git commit -m "test: add inner-layer libFuzzer harnesses (XML, VariantDict, BlockStream)"
```

---

## Task 8: Seed generator

**Files:**
- Create: `Fuzz/Sources/FuzzSeedGen/main.swift`

Produces plaintext seeds for the inner targets that can't be seeded by copying `.kdbx` files. The XML seed is obtained by unlocking a fixture with `retainsXMLForDiagnostics: true`; the VariantDict seed by serializing a recommended KDF profile. BlockStream is left to start from an empty corpus (KDBX 3.x has no writer to synthesize a seed from; documented in the README).

- [ ] **Step 1: Confirm the helpers this task relies on**

Run:

```bash
cd /Users/denis/dev/info.ddenis/PasswordManager/KDBXKit
grep -rn "func recommended\|enum Profile\|struct VariantDictionaryWriter\|func serialize\|func write\|func encode" Sources/KDBXKit/Header/KDFParameters+Profile.swift Sources/KDBXKit/Header/VariantDictionaryWriter.swift
```

Expected: a `KDFParameters.recommended(_:)` (or similar profile factory) and a `VariantDictionaryWriter` with a serialize/encode entry point. Use the exact names found here in Step 2. If `VariantDictionaryWriter` has no usable public-or-`@testable` byte-producing method, skip the VariantDict seed (leave its corpus empty) and note it.

- [ ] **Step 2: Write the seed generator**

Create `Fuzz/Sources/FuzzSeedGen/main.swift`. The fixture password for `simple-argon2id-aes256.kdbx` must be confirmed (Step 3); the template uses `FUZZ_FIXTURE_PASSWORD`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// Writes plaintext seed corpora for the inner-layer fuzz targets. Run via
// run-fuzz.sh before a campaign. Args: <fixture.kdbx> <password> <corpus-root>

import Foundation
@testable import KDBXKit

let args = CommandLine.arguments
guard args.count == 4 else {
    FileHandle.standardError.write(Data("usage: FuzzSeedGen <fixture.kdbx> <password> <corpus-root>\n".utf8))
    exit(2)
}
let fixturePath = args[1]
let password = args[2]
let corpusRoot = URL(fileURLWithPath: args[3])

let data = try Data(contentsOf: URL(fileURLWithPath: fixturePath))

// XML seed: unlock with diagnostics retained, then dump the plaintext XML.
var reader = KDBXReader(data)
_ = try reader.parse(unlockData: UnlockData(masterPassword: password), retainsXMLForDiagnostics: true)
if let xml = reader.xmlDocument {
    let dst = corpusRoot.appendingPathComponent("xml/seed-fixture.xml")
    try Data(xml.utf8).write(to: dst)
    print("wrote XML seed (\(xml.utf8.count) bytes) -> \(dst.path)")
}
```

If Step 1 found a usable `VariantDictionaryWriter`, append a block that builds `KDFParameters.recommended(...)`, calls `.toVariantDictionary()`, serializes it with the writer, and writes the bytes to `corpusRoot/variantdict/seed-kdf.bin`, using the exact method names found.

- [ ] **Step 3: Confirm the fixture password**

Run:

```bash
grep -rn "simple-argon2id-aes256\|masterPassword" Tests/KDBXKitTests/*.swift | grep -i "password\|simple-argon2id" | head
```

Expected: the literal password used to unlock `simple-argon2id-aes256.kdbx` in the existing tests. Substitute it for `FUZZ_FIXTURE_PASSWORD` in `run-fuzz.sh` (Task 9). If no fixture has a known password in-tree, use `demo.kdbx` from `Examples/HelloKDBX` and its documented password instead.

- [ ] **Step 4: Verify it builds and runs (Xcode toolchain is fine — no sanitizer here)**

Run: `KDBXKIT_FUZZ=1 swift run FuzzSeedGen Tests/KDBXKitTests/Resources/simple-argon2id-aes256.kdbx <password> Fuzz/corpus`
Expected: prints "wrote XML seed ..." and `Fuzz/corpus/xml/seed-fixture.xml` exists and is non-empty.

- [ ] **Step 5: Commit**

```bash
git add Fuzz/Sources/FuzzSeedGen
git commit -m "test: add fuzz seed generator for inner-layer corpora"
```

---

## Task 9: `run-fuzz.sh` wrapper

**Files:**
- Create: `Fuzz/run-fuzz.sh`

- [ ] **Step 1: Write the script**

Create `Fuzz/run-fuzz.sh`:

```bash
#!/usr/bin/env bash
#
# Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
# SPDX-License-Identifier: BSD-2-Clause
#
# Build and run a KDBXKit libFuzzer target. The Xcode toolchain cannot build
# libFuzzer targets, so this pins the swift.org toolchain.
#
# Usage: Fuzz/run-fuzz.sh <header|parse|xml|variantdict|blockstream> [seconds]

set -euo pipefail

TARGET_KEY="${1:?usage: run-fuzz.sh <header|parse|xml|variantdict|blockstream> [seconds]}"
DURATION="${2:-60}"

case "$TARGET_KEY" in
  header)      TARGET=FuzzHeader ;;
  parse)       TARGET=FuzzParse ;;
  xml)         TARGET=FuzzXML ;;
  variantdict) TARGET=FuzzVariantDict ;;
  blockstream) TARGET=FuzzBlockStream ;;
  *) echo "unknown target: $TARGET_KEY" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

TOOLCHAIN="$HOME/Library/Developer/Toolchains/swift-6.1.2-RELEASE.xctoolchain"
SWIFT="$TOOLCHAIN/usr/bin/swift"
SDK="$(xcrun --show-sdk-path)"
if [[ ! -x "$SWIFT" ]]; then
  echo "swift.org toolchain not found at $TOOLCHAIN" >&2
  echo "Install a swift.org release toolchain (libFuzzer is unsupported by Xcode's)." >&2
  exit 1
fi

CORPUS="Fuzz/corpus/$TARGET_KEY"
CRASHERS="Fuzz/crashers/$TARGET_KEY"
mkdir -p "$CORPUS" "$CRASHERS"

# Seed header/parse corpora from the golden fixtures (idempotent).
if [[ "$TARGET_KEY" == "header" || "$TARGET_KEY" == "parse" ]]; then
  cp -n Tests/KDBXKitTests/Resources/*.kdbx "$CORPUS"/ 2>/dev/null || true
fi

echo "Building $TARGET with libFuzzer + ASan (swift.org toolchain)..."
KDBXKIT_FUZZ=1 "$SWIFT" build \
  --sdk "$SDK" \
  --product "$TARGET" \
  -Xswiftc -sanitize=fuzzer \
  -Xswiftc -sanitize=address \
  -Xswiftc -parse-as-library \
  -Xswiftc -enable-testing \
  -Xcc -fsanitize=fuzzer-no-link

BIN="$(KDBXKIT_FUZZ=1 "$SWIFT" build --sdk "$SDK" --product "$TARGET" --show-bin-path)/$TARGET"

echo "Running $TARGET for ${DURATION}s (crashers -> $CRASHERS)..."
"$BIN" \
  -max_total_time="$DURATION" \
  -timeout=10 \
  -rss_limit_mb=2048 \
  -artifact_prefix="$CRASHERS/" \
  "$CORPUS"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x Fuzz/run-fuzz.sh`

- [ ] **Step 3: Smoke-run the header target**

Run: `Fuzz/run-fuzz.sh header 15`
Expected: builds via the swift.org toolchain, prints libFuzzer banner (`INFO: Loaded ... modules`, rising `cov:`), runs ~15s, exits 0 with no crasher written. If the build fails with `-enable-testing`/`@testable` errors for `header`/`parse` (which don't use `@testable`), that's fine — the flag is harmless. If a crasher IS found, that is a real bug — capture it (it lands in `Fuzz/crashers/header/`) and triage before proceeding.

- [ ] **Step 4: Smoke-run one inner target (uses @testable + seed gen)**

Run: `Fuzz/run-fuzz.sh variantdict 15`
Expected: builds and runs. (VariantDict corpus may be empty if Task 8 skipped its seed — libFuzzer starts from empty, which is acceptable.)

- [ ] **Step 5: Commit**

```bash
git add Fuzz/run-fuzz.sh
git commit -m "test: add run-fuzz.sh wrapper pinning swift.org toolchain"
```

---

## Task 10: Deterministic crasher-replay regression suite

**Files:**
- Create: `Tests/KDBXKitTests/FuzzRegressionTests.swift`

This runs in plain `swift test` / CI. It loads every checked-in crasher and asserts the corresponding parser handles it without crashing — so fixed crashers never regress even though campaigns are on-demand. Initially the crasher dirs are empty, so the suite is a no-op that proves the wiring.

- [ ] **Step 1: Write the test**

Create `Tests/KDBXKitTests/FuzzRegressionTests.swift`:

```swift
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Replays libFuzzer crashers checked into `Fuzz/crashers/<target>/`. Each file
/// is a byte blob that once crashed a parser; feeding it back must now produce a
/// typed error or a clean result — never a trap. Runs in normal `swift test`.
@Suite("Fuzz regression — checked-in crashers stay fixed")
struct FuzzRegressionTests {
    /// Walk up from this source file to the repo root, then into Fuzz/crashers.
    private static func crasherFiles(target: String) -> [URL] {
        let here = URL(fileURLWithPath: #filePath)
        let repoRoot = here
            .deletingLastPathComponent() // KDBXKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root
        let dir = repoRoot.appendingPathComponent("Fuzz/crashers/\(target)")
        let contents = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return contents.filter { $0.lastPathComponent != ".gitkeep" }
    }

    private func data(of url: URL) throws -> Data { try Data(contentsOf: url) }

    @Test func headerCrashersAreHandled() throws {
        for url in Self.crasherFiles(target: "header") {
            _ = try? KDBXReader.parseHeader(try data(of: url))
        }
    }

    @Test func parseCrashersAreHandled() throws {
        let unlock = UnlockData(masterPassword: "fuzz")
        let tiny = KDFParameterLimits(maxArgon2Memory: 1 << 20, maxArgon2Iterations: 2, maxArgon2Parallelism: 2, maxAESKDFRounds: 10_000)
        for url in Self.crasherFiles(target: "parse") {
            _ = try? KDBXReader.parse(try data(of: url), unlockData: unlock, kdfLimits: tiny)
        }
    }

    @Test func variantDictCrashersAreHandled() throws {
        for url in Self.crasherFiles(target: "variantdict") {
            var reader = VariantDictionaryReader(data: try data(of: url))
            _ = try? reader.parse()
        }
    }

    @Test func blockStreamCrashersAreHandled() throws {
        for url in Self.crasherFiles(target: "blockstream") {
            _ = try? HashedBlockStreamReader.decode(try data(of: url))
        }
    }

    @Test func xmlCrashersAreHandled() throws {
        let keystream = KeystreamSource(algorithm: .chacha20, key: SecureBytes(Data(repeating: 0, count: 32)), nonce: Data(repeating: 0, count: 12))
        for url in Self.crasherFiles(target: "xml") {
            guard let xml = String(data: try data(of: url), encoding: .utf8) else { continue }
            let reader = try? XMLDocumentReader(xmlDocument: xml, keystreamSource: keystream)
            _ = try? reader?.parse()
        }
    }
}
```

(If Step 2 of Task 7 found `parse()` non-mutating, change `var reader` to `let reader` here too, matching the harness.)

- [ ] **Step 2: Run it**

Run: `swift test --filter FuzzRegressionTests`
Expected: PASS (5 tests, each a no-op while crasher dirs hold only `.gitkeep`). The point is that the loader compiles and finds the directories.

- [ ] **Step 3: Commit**

```bash
git add Tests/KDBXKitTests/FuzzRegressionTests.swift
git commit -m "test: replay checked-in fuzz crashers as a regression gate"
```

---

## Task 11: Documentation

**Files:**
- Create: `Fuzz/README.md`

- [ ] **Step 1: Write the README**

Create `Fuzz/README.md`:

````markdown
# KDBXKit fuzzing

Coverage-guided (libFuzzer) fuzz targets over KDBXKit's parsing surfaces. They
assert one invariant everywhere: the parser returns a typed error or a clean
result — it never traps and never hangs.

## Toolchain requirement

The Xcode Swift toolchain **cannot** build libFuzzer targets (`-sanitize=fuzzer`
is rejected for `*-apple-macosx`). Install a swift.org release toolchain; the
wrapper pins `~/Library/Developer/Toolchains/swift-6.1.2-RELEASE.xctoolchain`.
Download from https://www.swift.org/download/ if absent.

## Running a campaign

```bash
Fuzz/run-fuzz.sh <header|parse|xml|variantdict|blockstream> [seconds]
```

Targets:

| Key           | Surface                                   |
|---------------|-------------------------------------------|
| `header`      | `KDBXReader.parseHeader`                  |
| `parse`       | full `KDBXReader.parse` pipeline          |
| `xml`         | post-decryption XML reader                |
| `variantdict` | header VariantDictionary reader           |
| `blockstream` | KDBX 3.x hashed-block stream decoder      |

The fuzz targets are gated behind `KDBXKIT_FUZZ=1`, so they never affect a
normal `swift build` / `swift test` / Xcode build.

## Corpora and seeds

- `Fuzz/corpus/<target>/` — the input corpus. `header`/`parse` are auto-seeded
  from `Tests/KDBXKitTests/Resources/*.kdbx`. Inner-layer plaintext seeds are
  produced by `FuzzSeedGen`. `blockstream` starts from an empty corpus and is
  populated by discovery.
- `Fuzz/crashers/<target>/` — captured crashers. **Check these in.**

## Triaging a crasher

1. libFuzzer writes the offending input to `Fuzz/crashers/<target>/crash-<hash>`.
2. Reproduce: `<built-binary> Fuzz/crashers/<target>/crash-<hash>`.
3. Fix the parser so it throws a typed error instead of trapping.
4. Keep the crasher file checked in — `FuzzRegressionTests` (runs in
   `swift test`) replays every file here and asserts it stays fixed.

## KDF denial-of-service note

KDF cost is bounded by `KDFParameterLimits`, enforced in
`UnlockData.computeUnlockKey` (default `.default`, ~1 GiB Argon2 memory). The
`parse` fuzz target passes a tiny limit so the engine explores the parser
rather than the KDF.
````

- [ ] **Step 2: Verify links/paths**

Run: `test -f Fuzz/run-fuzz.sh && test -d Fuzz/corpus/header && echo OK`
Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add Fuzz/README.md
git commit -m "docs: document KDBXKit fuzzing workflow"
```

---

## Final verification

- [ ] **Normal build/test unaffected:** `swift build && swift test` — all green, fuzz targets absent.
- [ ] **Gate works:** `KDBXKIT_FUZZ=1 swift package describe --type json | grep -c FuzzHeader` → `1`.
- [ ] **Each target runs:** `for t in header parse xml variantdict blockstream; do Fuzz/run-fuzz.sh $t 20; done` — each builds via the swift.org toolchain and runs without an unexpected crasher. Any crasher found is a real bug: triage per the README before declaring done.
- [ ] **Regression suite green:** `swift test --filter FuzzRegressionTests`.
- [ ] **Format:** `mint run swiftformat .` then re-run `swift build` and commit any formatting deltas.

## Out of scope (per spec)

CI integration, dictionary/structure-aware mutators, and fuzzing the writer path are deliberately excluded.
