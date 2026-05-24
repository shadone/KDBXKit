# KDBX compatibility matrix

What KDBXKit can open, what it produces, and how faithfully it round-trips — the
interop reference. For the byte-level container and XML detail behind these rows, see
[spec/kdbx-container.md](spec/kdbx-container.md) and [spec/kdbx-xml.md](spec/kdbx-xml.md)
(with [spec/KDBX_XML.xsd](spec/KDBX_XML.xsd)). For crypto detail see [security.md](security.md).

KDBXKit is interop-tested against KeePassXC's `keepassxc-cli` (a gated test suite) and
fuzz-tested against malformed input.

## Format version

| Version | Read | Write |
|---|---|---|
| KDBX 4.1 | yes (lazy + eager) | yes — **always** |
| KDBX 4.0 | yes (lazy + eager) | no (writer emits 4.1) |
| KDBX 3.1 | yes (**eager only** — the lazy/metadata-only reader rejects 3.x, as its inline-XML binary pool has no lazy analog) | no |
| KDBX 2.x / KeePass 1.x (`.kdb`) | no | no |

The writer always emits KDBX 4.1, so reading a 3.1 file and writing it back upgrades it.

## Outer cipher

| Cipher | Read | Write |
|---|---|---|
| AES-256-CBC | yes | yes |
| ChaCha20 | yes | yes |
| Twofish | no | no |

## Key derivation (KDF)

| KDF | Read | Write |
|---|---|---|
| Argon2d | yes | yes |
| Argon2id | yes | yes |
| AES-KDF | yes | yes |

## Inner-stream (memory-protection) cipher

| Cipher | Read | Write |
|---|---|---|
| ChaCha20 | yes | yes (default) |
| Salsa20 | yes (legacy) | no (writer emits ChaCha20) |

## Compression

| Mode | Read | Write |
|---|---|---|
| gzip | yes | yes |
| none | yes | yes |

## Composite key (unlock sources)

| Source | Supported |
|---|---|
| Master password | yes |
| Key file — XML v2 (`<Data Hash=…>base64</Data>`) | yes (checksum verified) |
| Key file — XML v1 (`<Data>HEX</Data>`) | yes |
| Key file — raw 32 bytes | yes |
| Key file — 64 ASCII hex chars | yes |
| Raw 32-byte pre-hash (e.g. biometric-unlocked Keychain) | yes |
| Challenge-response (YubiKey HMAC-SHA1) | no — see note |

## Data model (read and write)

All modeled and round-tripped:

- **Groups** — nesting, ordering, default Auto-Type sequence, enable flags (`NullableBoolEx`).
- **Entries** — standard fields plus arbitrary **custom string fields**, each plaintext or protected (XOR-masked by the inner-stream cipher).
- **Times** — created / modified / accessed / expiry / usage count / location-changed. Second precision; **sub-second precision is not preserved**.
- **Binaries / attachments** — the deduplicated binary pool, with a streaming reader/writer that keeps binaries off the heap.
- **Custom icons**, **entry history** (capped by `HistoryMaxItems` / `HistoryMaxSize`), **tags**, **Auto-Type**, foreground/background **color**, **override URL**, previous-parent-group.
- **Recycle Bin** (`Meta/RecycleBinUUID`) and **DeletedObjects** (sync tombstones).
- **CustomData** at database, group, and entry level.

## Round-trip fidelity

- **Unknown CustomData items** written by other apps: **preserved** on read-modify-write (required by the spec).
- **Tombstones** (`DeletedObjects`) and **entry / group order**: preserved.
- **Unknown top-level XML elements** (anything outside the modeled set and CustomData): **not guaranteed** to survive a round-trip.
- **Sub-second timestamps**: not preserved (second precision).
- Reading a KDBX 3.1 file and writing produces KDBX 4.1.

## Not supported

- Writing KDBX 3.1 or 2.x; reading or writing KeePass 1.x (`.kdb`).
- Twofish outer cipher.
- Challenge-response (YubiKey HMAC-SHA1) key source — see note below.
- Guaranteed preservation of unknown, non-CustomData XML elements.

### Note: challenge-response / YubiKey

The composite key is built only from a password and/or key file: `UnlockData`
derives `R = SHA-256(SHA-256(password) || keyfile)` and runs the KDF on `R`. There is
no extension point to fold an additional key component into `R`, and the only
precomputed-key escape hatch (`UnlockData(rawKeyData:)`) takes a *static* 32-byte value.

Talking to the hardware token is the app's job, but KeePassXC-compatible
challenge-response also needs format-engine support that KDBXKit does not yet have:
the challenge is derived from per-save file material (so the response can't be
precomputed), which means KDBXKit would need to (1) expose that challenge during
unlock and accept a caller-supplied response folded into the composite key, and
(2) re-challenge on write after a fresh seed is generated. Until those hooks exist,
YubiKey-protected databases can't be opened or written.

## See also

- [README.md](../README.md) — the `Features` summary table and library usage.
- [spec/kdbx-container.md](spec/kdbx-container.md) — outer container, headers, KDF/cipher framing.
- [spec/kdbx-xml.md](spec/kdbx-xml.md) — the inner XML payload, element by element.
- [security.md](security.md) — crypto primitives and memory handling.
