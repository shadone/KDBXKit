# Migrating protected values to KDBXKit 2.0

2.0 changes the protected-value enum representations. Existing constructor calls
are kept as deprecated factories; exhaustive switches require migration. This is
an API migration, not a new vault format: existing KDBX 3.1/4.x files remain readable,
and both writer paths continue producing compatible KDBX 4.x files.

| Previous constructor/case | Preferred API |
|---|---|
| `Value.unprotected(String or SecureBytes)` | `Value.innerProtected(...)` |
| `Value.protectedInMemory(...)` | `Value.memoryProtected(...)` |
| `Value.inline(data, protected: flag)` | `Value.makeInline(data, protected: flag)` |
| `case .inline(data, protected)` | `case .plainInline`, `.protectedInline`; inspect metadata separately |

`innerProtected` retains resident ciphertext and serializes inner-stream-encrypted
XML. `memoryProtected` retains resident ciphertext but preserves the XML-only
ProtectInMemory hint: its XML is plaintext inside the encrypted outer vault.
For a password or other secret requiring inner protection, choose innerProtected.
Parsed inner-protected fields remain lazy ciphertext until revealed.

For binaries, use `inlineByteCount`/`isProtected` for metadata, `inlineData` for an
explicit plaintext copy, and BinaryContent.withRevealedBytes for scoped work.
BinaryContent.inlineValue shares encrypted storage with an entry/history without
first decrypting the pool. Setting a pool's protection flag or data property
updates its storage policy. DataBinarySource honors the same flag while resident.

ProtectedBytes uses the existing Swift Crypto dependency's ChaChaPoly with an
independent generated key and automatic nonce for each immutable payload.
The key is held by SecureBytes. Reveals return fresh zero-on-release SecureBytes;
explicit Data/String compatibility accessors remain available at use boundaries.

These APIs reduce plaintext residence; they cannot defeat a compromised process
that reads ciphertext and keys. mlock is best effort. Source buffers are not erased,
closures can return copies, and XML parsing, crypto libraries, UI, export and streaming
operations may materialize transient plaintext. Swift/String/Data copies cannot be
promised to disappear synchronously. Diagnostic XML retention is explicitly unsafe
for secrets and remains opt-in. Do not keep plaintext accessor results in model state.

The CLI's historical JSON protection labels remain stable for consumers. A masked
field is classified without decrypting it. The obsolete generic `.unprotected`
name no longer represents a runtime storage case.

References: [KeePass format](https://keepass.info/help/kb/kdbx.html),
[Swift Crypto ChaChaPoly](https://apple.github.io/swift-crypto/docs/current/Crypto/Enums/ChaChaPoly.html).
