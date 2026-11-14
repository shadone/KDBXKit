# Security Primitives

How KDBXKit limits plaintext residence and handles explicitly revealed values.

## Overview

``SecureBytes`` holds zero-on-release plaintext buffers and keys. ``ProtectedBytes``
retains authenticated ciphertext with an independent generated key/nonce.
``KDBX/ProtectedString`` and ``KDBX/ProtectedBinary`` distinguish wire-format flags
from resident storage. These types do not eliminate plaintext during use, and
cannot defend a compromised process that can read keys and ciphertext together.

## SecureBytes

Small buffers share page-aligned arenas; large ones get dedicated regions.
The pages use best-effort mlock, and each owned slice is erased on final release
with platform non-elidable zeroing. A failed mlock does not prevent allocation.
Read access is scoped through withUnsafeBytes; equality compares the byte contents
in constant time. Explicit toData/revealedString accessors create caller-owned
plaintext copies and must be used with care.

```swift
let bytes = SecureBytes(utf8: "typed at the boundary")
bytes.withUnsafeBytes { buffer in
    // Consume buffer here; do not retain its pointer.
}
```

Data/UTF-8 constructors copy directly into the arena, without intermediate
plaintext arrays. The generic Sequence constructor erases its scratch array.
None of these constructors erase the caller's source value.

## Protected strings

```swift
let secret = KDBX.ProtectedString.Value.innerProtected("new password")
let note = KDBX.ProtectedString.Value.regular("public note")
let memoryHint = KDBX.ProtectedString.Value.memoryProtected("XML-only hint")

secret.withRevealedString { plaintext in
    // Use it only for the intended operation; do not retain or log it.
}
```

innerProtected stores encrypted resident bytes and serializes inner-stream
ciphertext with Protected=True. Parsed protected XML values remain lazy inner
ciphertext until requested. regular stores SecureBytes and writes clear XML;
it is inappropriate when a field must have inner-stream protection. memoryProtected
stores encrypted resident bytes but preserves ProtectInMemory=True and clear XML,
inside the outer encrypted vault. It is a different wire-format hint.

In 2.0, unprotected/protectedInMemory remain deprecated constructor factories,
not enum cases. They construct the corresponding encrypted resident values.
Exhaustive switches must migrate to the new cases. Explicit bytes/revealedString
accessors can let plaintext escape; scoped closures express intent, not a language
restriction preventing copying.

## Protected attachments

Use ProtectedBinary.Value.makeInline(data, protected: flag). Protected payloads
retain ProtectedBytes; unprotected payloads use plainInline. The deprecated inline
constructor also honors the flag. BinaryContent and DataBinarySource enforce the
same policy. Pool inlineValue shares encrypted storage with entries/history.

Use inlineByteCount/count and isProtected for metadata without revealing content.
Use withRevealedBytes for a scoped operation or a SecureBytesSink for extraction.
Explicit inlineData/BinaryContent.data reads create plaintext copies for callers.
The pool's memory flag does not add inner-stream encryption to on-disk pool bytes;
those bytes are protected by the outer vault cipher.

## Limits

- A debugger, memory reader or compromised process can obtain keys and plaintext.
- Source Strings/Data and copies escaping reveal closures cannot be erased by us.
- XML parsing, cryptographic SDKs, UI, export and streaming have transient plaintext
  working data; Swift/ARC cannot promise every internal copy vanishes synchronously.
- Opt-in diagnostic XML retention keeps plaintext and must not be used routinely.
- mlock is best effort. Zero-on-release protects owned buffers, not arbitrary
  allocator/stack/SDK copies or an application that deliberately retains a reveal.

The CLI does not reveal a field it will only print as masked. Applications should
likewise avoid decrypting for metadata and never store plaintext accessor results
in model state.

## Other primitives

ConstantTime supplies secret-derived comparisons, SecureRandom provides system
entropy for format salts/IVs, and ``SecureBytesSink`` bounds extraction buffers.
The file-format inner stream and per-value resident protection have separate keys
and purposes; resident protection does not change the KDBX format.
