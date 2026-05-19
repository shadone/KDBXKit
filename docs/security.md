# Security

KDBXKit handles password-manager databases — files designed to carry highly sensitive secrets through hostile environments. This document is the engineering posture: what KDBXKit does to protect those secrets, what guarantees it provides, and where the limits are.

## Posture

KDBXKit's job, end-to-end, is to:

1. Accept credentials (password and/or key file), derive an unlock key, and discard the cleartext as fast as possible.
2. Verify a vault's integrity *before* trusting any of its contents.
3. Decrypt the vault into memory in a form that won't bleed to swap, allocator reuse, or arbitrary `Swift.String` lifetimes.
4. Re-encrypt and write back with freshly generated salts and IVs, never reusing nonces.
5. Crash-free on malformed input, no matter how adversarial.

Everything in this document is in service of one of those five.

## Credential lifecycle

```
User-typed password (Swift.String, transient)
        │
        ▼
UnlockData.init(masterPassword:)            ← consumes the String
        │  R = SHA-256(SHA-256(pwBytes) || keyFile)
        ▼
SecureBytes (32 bytes, mlock'd, zero-on-deinit)   ← the pre-hash
        │
        ▼
KDF (Argon2id / Argon2d / AES-KDF)
        │
        ▼
SecureBytes (32 bytes, the unlock key)
        │
        ▼
HMAC-SHA-256 over file header       ← verify integrity *before* decrypt
        │
        ▼
AES-256-CBC or ChaCha20 decrypt the block stream
        │
        ▼
KDBXContent (entry strings live in ProtectedString.Value)
        │
        ▼
Caller reveals via withRevealedString { … }   ← scoped, not a getter
        │
        ▼
SecureBytes deinit → memset_s / explicit_bzero → free
```

The cleartext password lives only inside the `UnlockData.init` call frame. The 32-byte pre-hash from there on is the authority; the password itself is gone.

## Memory hygiene

### `SecureBytes`

Defined in `Sources/KDBXKit/Crypto/SecureBytes.swift`. Every key-material buffer in the library is a `SecureBytes`:

- Allocated with `posix_memalign` on a page boundary.
- `mlock(2)`-pinned so the kernel can't page it to swap. Failure is silent (some platforms refuse via `RLIMIT_MEMLOCK`); a non-pinned page still holds the bytes — it just isn't protected against the swap-disclosure path.
- Zeroed on `deinit` via `memset_s(3)` on Apple/BSD (C11 Annex K, defined as not-optimizable-away) or `explicit_bzero(3)` on Linux (glibc ≥ 2.25 / musl ≥ 1.1.20). Then `munlock`'d, then `free`'d.
- Read access only through `withUnsafeBytes { … }` — no `subscript`, no `Data` getter — so callers can't escape the buffer past its zeroed lifetime.
- `Equatable` via constant-time comparison: every byte XOR-OR'd into an accumulator; no short-circuit. Equality on two `SecureBytes` does not leak content via timing.

### `ProtectedString.Value`

Defined in `Sources/KDBXKit/KDBX/ProtectedString.swift`. Entry-level secrets (passwords, TOTP seeds, custom protected strings) are stored as `ProtectedString.Value`, never as `String`.

- The reveal API is `func withRevealedString<R>(_ body: (String) throws -> R) rethrows -> R`. The lifetime of the cleartext `String` is bounded by the closure.
- A convenience `var revealedString: String` exists for ergonomics, but the closure form is the documented pattern. Code review treats a bare `.revealedString` as a smell unless the use site immediately consumes it.
- The underlying bytes are held as `SecureBytes`, so anything that derives from a `ProtectedString.Value` inherits the page-locked + secure-zero guarantees.

### What we *don't* try to protect

Once a host passes a cleartext `String` into `UnlockData(masterPassword:)`, the bytes of that `String` are reachable in process memory until ARC collects it — and Swift `String`'s storage can't be securely zeroed. Treat the `init` call site as the boundary: get the typed password into KDBXKit fast, drop the original `String` reference, and let GC do its thing. `withRevealedString { … }` callers face the same constraint at the other end: anything the closure does with the `String` is outside our control.

## Cryptographic primitives

Everything in this table is either delegated to a widely-vetted upstream, vendored from the spec authors' reference C, or implemented as a constant-time stream loop.

| Use | Algorithm | Implementation |
|---|---|---|
| Outer cipher | AES-256-CBC | swift-crypto `AES._CBC` (BoringSSL-backed) |
|              | ChaCha20    | `Sources/KDBXKit/Crypto/ChaCha20.swift` (RFC 7539) |
| Inner stream | Salsa20     | `Sources/KDBXKit/Crypto/Salsa20.swift` |
|              | ChaCha20    | same as outer |
| KDF | AES-KDF | swift-crypto `AES.permute` (single-block) over `Sources/KDBXKit/KDF/AESKDF.swift` |
|     | Argon2d / Argon2id | vendored P-H-C reference C in `Sources/CArgon2/` |
| MAC | HMAC-SHA-256 | swift-crypto `HMAC<SHA256>` |
| Hash | SHA-256, SHA-512 | swift-crypto |
| CSPRNG | OS entropy | Swift's `SystemRandomNumberGenerator` (`arc4random_buf`/`getentropy` on Apple, `getrandom(2)` on Linux) |
| Constant-time compare | XOR-OR accumulate | `Sources/KDBXKit/Crypto/ConstantTime.swift` |

The two algorithms we implement ourselves — Salsa20 and ChaCha20 — are byte-stream ciphers that XOR a keystream against input. The Swift code is a direct transcription of the RFC reference and takes the same code path for every byte regardless of value. We don't implement any block cipher, KDF, MAC, or hash.

## Integrity before content

KDBX 4's outer block stream is HMAC-SHA-256 protected per block. KDBXKit verifies the HMAC *before* doing anything with the bytes inside:

1. Read encrypted block.
2. Compute expected HMAC from the block index, block size, and the unlock-key-derived HMAC key.
3. **Compare in constant time.** Any mismatch aborts immediately as `KDBXReader.Error.corruptedHMAC`.
4. Only then: decrypt with AES/ChaCha20, decompress with gzip, parse the inner header, parse the XML.

This ordering matters. If we decrypted-then-verified, a wrong-key attempt would feed garbage into the decompressor — exposing zlib to adversarial input it shouldn't see and potentially leaking timing or error signals on its failure paths. HMAC-first means a wrong key is rejected before any byte of cleartext-shape data is processed.

KDBX 3.x has no HMAC, only a "StreamStartBytes" sentinel. KDBXKit treats a wrong sentinel as wrong-credentials and refuses to process further. The library writes only KDBX 4.x — if you save a 3.x file, it's migrated to 4.1 with full HMAC protection.

## Robustness against adversarial input

A malformed or crafted `.kdbx` file should fail with a typed error. Never a crash, never an unbounded allocation, never a hang.

- **Fuzz tests.** `Tests/KDBXKitTests/MalformedInputTests.swift` mutates fixture bytes and asserts every parse either succeeds or returns a `KDBXReader.Error`. No `fatalError`, no segfault.
- **Decompression cap.** `KDBXReader.maxDecompressedPayloadSize` (default 256 MB) bounds the gzip output. A crafted "zip bomb" payload fails mid-inflation with `decompressedPayloadTooLarge`, not after a runaway allocation. The cap is enforced inside the zlib loop, not after the fact.
- **Typed errors throughout.** `KDBXReader.Error` and `KDBXWriter.Error` are exhaustive enums. Caller-facing doc comments on each case describe what it signals. The library does not crash on any input we've been able to construct.
- **Interop tests as a divergence detector.** `Tests/KDBXKitTests/KeePassXCInteropTests.swift` drives the real `keepassxc-cli` against vaults we wrote and reads vaults `keepassxc-cli` wrote, asserting bytes-out and content-in round-trip cleanly. If a refactor breaks the format in a subtle way (e.g., a tag separator regression, an XML declaration omission), KeePassXC notices before we ship.

## Random number generation

Salts, IVs, and the inner-stream nonce are generated via Swift's `SystemRandomNumberGenerator`, which on Apple wraps `arc4random_buf` (which itself wraps `getentropy(2)`) and on Linux wraps `getrandom(2)`. Both are CSPRNG-quality OS entropy sources that don't block, don't run out, and don't need seeding.

On every save, fresh salts and IVs are generated. There is no nonce reuse across writes. (To produce byte-identical output for testing, callers pass `regenerateSalts: false` to `KDBXWriter.write` — this is for golden-file diffing only, never used in production.)

## What we deliberately don't defend

Honest scoping. These are out of KDBXKit's threat model:

- **Process-memory introspection.** Any attacker that can attach a debugger, `ptrace`, read `/proc/<pid>/mem`, or read a core dump can recover unlocked secrets. `SecureBytes` defends against swap and allocator reuse, not against an attacker at the same trust level as the host process.
- **Side channels in the host's use of `withRevealedString`.** Once a closure has a `String`, the host can copy it, log it, write it to a file. We can't prevent that; we just make the lifetime explicit.
- **Algorithm-level side channels in Argon2 or AES.** The vendored Argon2 is the reference implementation by the spec authors; swift-crypto's AES is BoringSSL. Both are widely deployed, but cache-timing and electromagnetic side channels are out of scope.
- **Network attackers.** KDBXKit never opens a socket.
- **FIPS 140-3.** swift-crypto's BoringSSL is not FIPS-certified.
- **Key-provider plugins.** The KeePass plugin ecosystem (YubiKey HMAC-SHA1 challenge-response, Windows DPAPI keys) is not supported. Credentials are password, key file, or the raw 32-byte pre-hash — nothing else.

---

Found a security issue? See [`SECURITY.md`](../SECURITY.md) at the repo root for how to report it.
