# Security Primitives

How KDBXKit handles credentials and other sensitive data in memory.

## Overview

A password-manager library has a different memory-management contract than a general-purpose library. Anything that touches cleartext key material — passwords, key files, derived keys, decrypted entry strings — needs to live in a buffer that won't bleed to swap, won't be handed to the next allocator caller still warm, and won't leak through Swift's standard `String` and `Data` types (neither of which can be securely zeroed).

KDBXKit's answer is two types: ``SecureBytes`` for arbitrary key material, and ``KDBX/ProtectedString`` for entry-level secrets. Both have a hard rule: **no cleartext crosses the API boundary as a `Swift.String`.**

For a wider view of the engineering posture (cryptographic primitives, integrity ordering, threat model), see the project's `docs/security.md`.

## SecureBytes

A page-aligned, `mlock`'d, zero-on-deinit byte buffer.

```swift
let bytes = SecureBytes(utf8: "secret")
bytes.withUnsafeBytes { buf in
    // use buf for the lifetime of this closure
}
// bytes' buffer is zeroed and freed when the last reference releases.
```

Properties:

- **Page-aligned allocation** via `posix_memalign` so the entire region can be `mlock`'d.
- **`mlock(2)`-pinned** so the kernel can't page the bytes to swap. Best-effort: if `RLIMIT_MEMLOCK` rejects the call (common on iOS background processes), the page still holds the bytes — it just isn't pinned. Failure is silent by design; refusing to unlock would be worse UX.
- **Zeroed on `deinit`** via `memset_s` on Apple/BSD or `explicit_bzero` on Linux. Both are functions the compiler is forbidden from optimizing away.
- **Read access only through `withUnsafeBytes`** — no subscript, no `Data` accessor — so callers can't escape the buffer past its lifetime.
- **Constant-time equality.** `==` XOR-OR-accumulates every byte; no short-circuit on first mismatch. Comparing two `SecureBytes` doesn't leak content via timing.

When in doubt: if it's key material or about to be, hold it in `SecureBytes`.

## ProtectedString

Entry-level secrets — passwords, TOTP seeds, custom protected strings.

```swift
let password = entry.strings.first(where: { $0.key == "Password" })?.value

password?.withRevealedString { plaintext in
    // `plaintext` is a Swift.String that lives only for this closure.
    keychain.set(plaintext, for: entry.uuid)
}
```

The closure form is the documented pattern. There's also `revealedString: String` and `bytes: SecureBytes` for ergonomic use, but `withRevealedString` makes the lifetime explicit at the call site.

The underlying bytes are held as ``SecureBytes``, so anything derived inherits the page-locked + secure-zero guarantees.

### Constructing protected values

```swift
let v1 = KDBX.ProtectedString.Value.regular("secret")            // standard protected
let v2 = KDBX.ProtectedString.Value.unprotected("public note")   // standard non-protected
let v3 = KDBX.ProtectedString.Value.protectedInMemory("secret")  // protected always
```

`.regular(_:)` is what you want most of the time — protected in memory and on disk for standard secret fields.

## What KDBXKit can't protect

`SecureBytes` and `withRevealedString` defend against specific failure modes — they don't make your process invulnerable.

- **Process-memory introspection.** Anything that can attach a debugger, `ptrace`, read `/proc/<pid>/mem`, or read a core dump can recover unlocked secrets. `SecureBytes` defends against swap and allocator reuse, not against an attacker with the same trust level as the host process.
- **What you do with `String` after revealing.** Once a closure has a `Swift.String`, the host can copy it, store it, log it. We can't prevent that. The closure form makes the lifetime intent explicit; honoring it is the host's job.
- **Password bytes during `UnlockData.init(masterPassword:)`.** Swift `String` storage can't be securely zeroed. Treat the init call site as a boundary: get the typed password into KDBXKit fast, drop the original `String` reference, and let ARC collect it.

## Other primitives

- ``KDBX/ProtectedBinary`` — attachment payloads that should be page-locked. Same memory contract as `ProtectedString`.
- `ConstantTime` (internal) — XOR-OR comparison used for HMAC verification and any other secret-derived comparison.
- `SecureRandom` (internal) — wraps `SystemRandomNumberGenerator` for salt / IV / nonce generation. CSPRNG-quality entropy on every supported platform.

For sink-level secure-byte handling during streaming binary extraction, see ``SecureBytesSink`` (a ``ByteSink`` whose buffer is itself a ``SecureBytes``).
