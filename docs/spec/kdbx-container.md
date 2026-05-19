# The KDBX 4.1 Container Format

## Abstract

This document specifies the binary container format used by KDBX files
version 4.0 and 4.1, the storage format of the KeePass family of password
managers. It covers the file signature, dynamic header, key derivation,
authenticated encryption, block stream framing, and inner header that
together wrap the encrypted XML payload. The XML payload is specified
in a companion document.

## Status of This Document

This document is a normative restatement of the KDBX container format,
cross-checked against the KDBXKit implementation
(<https://github.com/shadone/KDBXKit>) and against files produced by
KeePassXC and the official KeePass 2.x client. Where this document
conflicts with the official KeePass implementation, the official
implementation takes precedence and this document is in error.

The companion KeePass.info knowledge-base page
<https://keepass.info/help/kb/kdbx.html> remains the upstream source of
intent; this document is byte-precise where that page is descriptive.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [RFC2119].

Byte grammars are expressed in ABNF [RFC5234]. All multi-byte integer
fields in the KDBX container are little-endian unless explicitly stated
otherwise.

UUID values are stored on disk in **RFC 4122 [RFC4122] canonical byte
order** — i.e. the same byte order produced by reading the 8-4-4-4-12
hex string left-to-right and emitting each octet as it appears.
A UUID written canonically as `C9D9F39A-628A-4460-BF74-0D08C18A4FEA`
appears on disk as `C9 D9 F3 9A 62 8A 44 60 BF 74 0D 08 C1 8A 4F EA`.
This document quotes UUIDs in the canonical 8-4-4-4-12 form and refers
to the on-disk bytes only when illustrating a header dump.

Implementations using `Foundation.UUID` should note that KDBXKit's
internal byte-tuple representation of these UUIDs is byte-reversed
relative to RFC 4122 (see `KDFParameters.KDF.AES`,
`Extensions/UUID+uint128.swift`, `Extensions/Data+asUUIDLE.swift`).
This is an internal-only convention; the bytes serialised to and
parsed from the file remain in canonical RFC 4122 order.

Hexadecimal byte sequences are written in uppercase, grouped by four
bytes, separated by single spaces (e.g. `9AA2D903 B54BFB67`). String
literals in field values are UTF-8 unless explicitly stated otherwise.

## Terminology

- **Container** — the outer file layout described by this document:
  signature, header, HMAC-protected block stream, inner header, inner
  payload.
- **Inner payload** — the decrypted, decompressed byte stream
  consumed by the XML reader. Specified in the companion document.
- **Outer cipher** — the symmetric cipher encrypting the inner header
  and inner payload (AES-256-CBC or ChaCha20).
- **Inner stream cipher** — the keystream cipher that protects
  individual XML string values (ChaCha20 for KDBX 4.x, Salsa20 for
  KDBX 3.x).
- **Composite key** — `SHA-256(SHA-256(passwordBytes) || keyFileBytes)`,
  a 32-byte value derived from the user-supplied credentials before any
  KDF is applied.
- **Transformed key** — the 32-byte output of the KDF applied to the
  composite key with parameters from the header.
- **Main key** — `SHA-256(masterSalt || transformedKey)`, the symmetric
  key fed to the outer cipher.

## Document map

1. File signature
2. Format version
3. Dynamic outer header
4. Variant dictionary encoding
5. Composite key construction
6. Key derivation function
7. Main key and HMAC seed
8. Header authentication
9. Outer cipher modes
10. HMAC-protected block stream
11. Optional gzip compression
12. Inner header
13. Inner stream cipher
14. Inner payload boundary
15. Appendix A (informative): KDBX 3.1 read path
16. Appendix B (normative): Test vectors
17. References

## 1. File signature

A KDBX 4.x file MUST begin with the 12-byte sequence:

    9AA2D903 B54BFB67 <minor:UInt16> <major:UInt16>

The first two 32-bit words are the file-identifier signature (little-endian
written as `03 D9 A2 9A` and `67 FB 4B B5` respectively on disk; written
above in their value form for readability). The two trailing 16-bit fields
are the format version, minor first.

Implementations MUST reject a file whose first 8 bytes do not match this
signature with a parse-time error. They MUST NOT attempt heuristic recovery.

Implementation reference: `Header.swift` (signature constants),
`KDBXReader.swift` (signature check at parse entry).

## 2. Format version

The minor and major version fields are unsigned 16-bit little-endian
integers. Defined values:

- `3.1` — KDBX 3.1. Read-only support is OPTIONAL; producers MUST NOT
  emit 3.x. See Appendix A for the read path.
- `4.0` — KDBX 4.0. Variant dictionary KDF parameters, HMAC-protected
  block stream, inner header.
- `4.1` — KDBX 4.1. Adds custom-data timestamps, custom-icon names and
  modified times, and tag and override-URL fields on Group; does not
  change the container layout described in this document.

A reader MUST reject 3.0 (the ArcFour inner-stream variant) with a
parse-time error. A reader MUST reject any major version greater than the
highest it implements. A reader MAY accept any minor version of a major
version it implements, parsing fields it does not recognise as no-ops if
the document map permits (it does not — see Section 3 for the closed
record set).

Implementation reference: `KDBXReader.swift` (version dispatch),
`Header.swift §FormatVersion` (struct with `static let` members
`v3_1`, `v4_0`, `v4_1`).

## 3. Dynamic outer header

The dynamic header is a sequence of TLV (type-length-value) records
beginning immediately after the 12-byte signature/version prefix.

Each record has the structure:

    HeaderRecord = type:UInt8 length:UInt32-LE value:Byte[length]

The header is terminated by a record of type `0x00` (`EndOfHeader`)
whose value MUST be the 4-byte sequence `0D 0A 0D 0A`. No header record
MAY appear after `EndOfHeader`. The total length of the header,
including the signature, is the byte offset of the first byte after
`EndOfHeader`'s value; this length is the input to the header HMAC
(Section 8).

### 3.1 Defined header records (KDBX 4.x)

| ID | Name                  | Value type          | Cardinality | Notes |
|----|-----------------------|---------------------|-------------|-------|
| 0  | EndOfHeader           | Byte[4] = 0D0A0D0A  | exactly 1   | terminator |
| 2  | EncryptionAlgorithm   | UUID                | exactly 1   | outer cipher; see Section 9 |
| 3  | CompressionAlgorithm  | UInt32-LE           | exactly 1   | 0 = none, 1 = gzip |
| 4  | MasterSalt            | Byte[32]            | exactly 1   | regenerated on save |
| 7  | EncryptionNonce       | Byte[]              | exactly 1   | 16 bytes for AES-CBC; 12 bytes for ChaCha20; regenerated on save |
| 11 | KDFParameters         | VariantDictionary   | exactly 1   | see Section 4 |
| 12 | PublicCustomData      | VariantDictionary   | 0 or 1      | plugins only; readable without credentials |

IDs `1, 5, 6, 8, 9, 10` are reserved for legacy KDBX 3.x fields (see
Appendix A) and MUST NOT appear in KDBX 4.x files. IDs not listed
above are unknown. KDBXKit logs unknown IDs at debug level and skips
them; a strict reader MAY reject them with a parse error.

A KDBX 4.x writer MUST emit each `exactly 1` record exactly once. A
KDBX 4.x reader MUST reject a header with any required record missing
or any required record duplicated.

### 3.2 Record ordering

The dynamic header records (excluding `EndOfHeader`, which is always
last) MAY appear in any order. Compliant readers MUST NOT rely on
specific ordering. KDBXKit emits records in the order
`EncryptionAlgorithm, CompressionAlgorithm, MasterSalt,
EncryptionNonce, KDFParameters, PublicCustomData, EndOfHeader`; this
ordering is informative.

Implementation reference: `HeaderFieldType.swift` (record IDs and value
types), `HeaderReader.swift` (parsing loop and rejection rules),
`HeaderWriter.swift` (emission order).

## 4. Variant dictionary encoding

A variant dictionary is a length-prefixed key-value map used inside two
header records: `KDFParameters` (Section 6) and `PublicCustomData`
(Section 3.1). The same encoding is used in both places.

### 4.1 Grammar

    VariantDict   = Version Item* Terminator
    Version       = UInt16-LE        ; current value 0x0100 (major 1)
    Terminator    = 0x00
    Item          = Type:UInt8
                    KeyLen:Int32-LE Key:Byte[KeyLen]
                    ValueLen:Int32-LE Value:Byte[ValueLen]
    Type          = 0x04 / 0x05 / 0x08 / 0x0C / 0x0D / 0x18 / 0x42

The version field is read as a single UInt16 little-endian; the high
byte is the major version and MUST equal `0x01`. The low byte is the
minor version; a reader MUST accept any minor.

`KeyLen` is the byte length of the UTF-8-encoded key, stored as a
signed Int32 little-endian. A reader MUST reject any `KeyLen` that is
zero or negative. `ValueLen` is the byte length of the value as encoded
on disk, stored as a signed Int32 little-endian. A reader MUST reject
any `ValueLen` that is zero or negative.

The terminator byte `0x00` MUST be present; a stream that ends without
encountering `0x00` is a parse error (the reader MUST reject it with an
unexpected-EOF error).

### 4.2 Value types

| Tag  | Type      | Encoding                                  |
|------|-----------|-------------------------------------------|
| 0x04 | UInt32    | 4 bytes, little-endian                    |
| 0x05 | UInt64    | 8 bytes, little-endian                    |
| 0x08 | Bool      | 1 byte; 0x00 = false, 0x01 = true         |
| 0x0C | Int32     | 4 bytes, little-endian, two's complement  |
| 0x0D | Int64     | 8 bytes, little-endian, two's complement  |
| 0x18 | String    | UTF-8 bytes, no terminator                |
| 0x42 | ByteArray | raw bytes, no length prefix beyond ValueLen |

Unknown type tags SHOULD be skipped: KDBXKit reads the key and value
bytes (advancing the stream past the full item) and logs the unknown
type at debug level before continuing to the next item. A strict reader
MAY reject an unknown tag with a parse error instead.

### 4.3 Ordering and duplicate keys

Items MAY appear in any order. Implementations MUST NOT rely on
specific ordering. Duplicate keys within a single dictionary cause the
later value to silently overwrite the earlier one; KDBXKit does not
detect or reject duplicates. Writers SHOULD NOT emit duplicate keys.

Implementation reference: `VariantDictionary.swift`,
`VariantDictionaryValueType.swift`, `VariantDictionaryReader.swift`
(grammar enforcement), `VariantDictionaryWriter.swift` (emission).

## 5. Composite key construction

The credentials supplied by the user are reduced to a 32-byte
**composite key** before any KDF is applied. The composite key is the
input to Section 6.

### 5.1 Sources of credential material

A KDBX file accepts up to two credential sources, applied in this
order:

1. **Password** — a UTF-8 string. Its SHA-256 digest is computed over
   the raw UTF-8 bytes (no NUL terminator, no Unicode normalisation).
   Implementations MUST NOT apply Unicode normalisation; the bytes
   as typed are authoritative. If no password is supplied, this source
   contributes the empty byte sequence (NOT the SHA-256 of empty).
2. **Key file** — a file on disk. Its content is reduced to 32 bytes
   by the dialect rules in §5.2; the resulting 32 bytes contribute
   directly (not their SHA-256). If no key file is supplied, this
   source contributes the empty byte sequence.

The composite key is:

    CompositeKey = SHA-256( H(password) || keyFileBytes )

where `H(password)` is `SHA-256(passwordBytes)` if a password is
present and the empty sequence otherwise, and `keyFileBytes` is the
32-byte reduction of the key file if present and the empty sequence
otherwise. Concatenation precedes hashing.

[Implementation note: KDBXKit does not enforce a minimum of one
credential source at composite-key construction time. The `init`
overloads accept a password, a key file, or both. A file opened with
neither source present would produce a deterministic, all-zeros-like
composite key; callers are expected to gate on credential presence
before calling `UnlockData.init`.]

### 5.2 Key-file dialects

KDBXKit accepts five key-file dialects and chooses by content. The
dispatch has four branches, where the first branch internally handles
both XML dialects:

1. **XML key file (v1 or v2)** — detected by a prefix scan for
   `<KeyFile` in the first 256 bytes (files larger than 8 KB are
   excluded from XML parsing and fall through to the remaining
   branches). The `<Key><Data>` element is parsed; the version is
   determined by the presence of a `Hash` attribute on `<Data>`.

   - **XML v1** — no `Hash` attribute. The text content is
     interpreted as hex if it is exactly 64 hex characters after
     stripping whitespace; otherwise it is interpreted as Base64.
     The decoded result MUST be 32 bytes; any other length causes
     the XML parse to return nil and the file falls through to the
     next branch.

   - **XML v2** — `Hash` attribute present. The text content is
     Base64-decoded. The decoded result MUST be 32 bytes. The `Hash`
     attribute nominally carries the first 4 bytes of
     `SHA-256(decodedBytes)` as uppercase hex, but KDBXKit detects
     the attribute for version discrimination only and does not
     validate its value. An implementation MAY validate the hash and
     reject a mismatch; KDBXKit does not.

2. **Raw 32-byte file** — exactly 32 bytes on disk, used as-is.

3. **Hex-encoded 32 bytes** — exactly 64 bytes on disk, all ASCII
   hex digits (`0-9`, `A-F`, `a-f`), decoded to 32 bytes.

4. **Hashed fallback** — any other file content; the 32-byte value is
   `SHA-256(fileBytes)`. This dialect exists for interop with
   arbitrary files used as key material (e.g. files generated by the
   KeePassXC CLI by default).

A reader MUST attempt the branches in the order listed above and
commit to the first that succeeds. The hashed fallback is the
unconditional last resort and always succeeds.

Implementation reference: `UnlockData.swift` (`makeKeyData` for
composition, `normalizeKeyFile` for dialect dispatch,
`parseXMLKeyFile` for both XML dialects, `decodeHexKeyFile` for the
hex branch).

## 6. Key derivation function

The KDFParameters header record (Section 3.1, ID 11) is a
VariantDictionary containing a single mandatory key `$UUID`
(ByteArray, 16 bytes, RFC 4122 byte order) that selects the KDF, plus
KDF-specific parameter keys.

### 6.1 AES-KDF

UUID: `C9D9F39A-628A-4460-BF74-0D08C18A4FEA`

Parameters:

| Key | Type      | Meaning                         |
|-----|-----------|---------------------------------|
| `R` | UInt64    | rounds; MUST be > 0             |
| `S` | ByteArray | seed; MUST be exactly 32 bytes  |

Derivation: the composite key (Section 5) is split into two 16-byte
blocks. Each block is independently encrypted with AES-256-ECB under
key `S` for `R` rounds. The two encrypted 16-byte blocks are
concatenated and SHA-256'd to yield the 32-byte transformed key.

    transformedKey = SHA-256( ECB-encrypt^R(left16, key=S)
                           || ECB-encrypt^R(right16, key=S) )

where `left16` and `right16` are the first and second halves of the
32-byte composite key respectively, and `ECB-encrypt^R` denotes R
sequential single-block AES-256-ECB encryptions.

### 6.2 Argon2d

UUID: `EF636DDF-8C29-444B-91F7-A9A403E30A0C`

Parameters (Argon2 RFC 9106 [RFC9106] terminology):

| Key | Type      | Meaning                                               |
|-----|-----------|-------------------------------------------------------|
| `S` | ByteArray | salt; SHOULD be 16 to 32 bytes                        |
| `P` | UInt32    | parallelism                                           |
| `M` | UInt64    | memory in bytes                                       |
| `I` | UInt64    | iterations                                            |
| `V` | UInt32    | Argon2 version; MUST be `0x13` (version 1.3)          |
| `K` | ByteArray | optional secret key; OPTIONAL, often absent           |
| `A` | ByteArray | optional associated data; OPTIONAL, often absent      |

Output length is 32 bytes. The variant is Argon2d.

KDBXKit parses and validates `S`, `P`, `M`, `I`, and `V`. Version
`0x10` (Argon2 1.0) is explicitly rejected. The `K` and `A` keys, if
present, are retained in the `additional` pass-through dictionary but
are not forwarded to the Argon2 hash function in the current
implementation.

### 6.3 Argon2id

UUID: `9E298B19-56DB-4773-B23D-FC3EC6F0A1E6`

Parameters and rules are identical to Argon2d (§6.2); only the variant
selector differs. KDBXKit and the upstream KeePass clients RECOMMEND
Argon2id for new files.

### 6.4 Output

In all three cases, the KDF output is a 32-byte **transformed key**
consumed by Sections 7 and 8.

Implementation reference: `KDFParameters.swift` (UUID dispatch and key
names), `AESKDF.swift` (AES-KDF derivation), `Argon2KDF.swift` (Argon2
derivation via the in-tree `argon2` C target).

## 7. Main key and HMAC seed

Given the master salt (Section 3.1, ID 4) and the transformed key
(Section 6), two values are derived:

    mainKey  = SHA-256( masterSalt || transformedKey )
    hmacSeed = SHA-512( masterSalt || transformedKey || 0x01 )

`mainKey` is 32 bytes and is the symmetric key fed to the outer cipher
(Section 9). `hmacSeed` is 64 bytes and is the input to per-block HMAC
key derivation (Section 10) and to header authentication (Section 8).

The byte `0x01` trailing the SHA-512 input is normative. A reader that
omits or alters it will produce a wrong HMAC seed and reject all
correctly-encoded files.

[Implementation note: KDBXKit does not materialise `hmacSeed` as a
named value. The formula `SHA-512(masterSalt || transformedKey || 0x01)`
appears as the inner hash computed inside `HMACProtectedBlockStream.keyForBlock`,
which builds the buffer inline before hashing it. The factored form
above is correct but is a logical description of the intermediate step,
not a stored variable.]

Implementation reference: `MainKey.swift` (main key derivation),
`HMACProtectedBlockStream.swift` (HMAC seed inline computation).

## 8. Header authentication

KDBX 4.x authenticates the dynamic header (Sections 1–3, i.e. all
bytes from offset 0 through the end of the `EndOfHeader` value
inclusive) with an HMAC-SHA-256 keyed by a value derived from
`hmacSeed`.

### 8.1 Layout

Immediately after `EndOfHeader`'s value, the file contains:

    HeaderHash:Byte[32]   ; SHA-256(headerBytes) — integrity check;
                          ; readers MUST verify (see below)
    HeaderHMAC:Byte[32]   ; the authenticated MAC

[Implementation note: KDBXKit verifies `HeaderHash` using
`ConstantTime.equals` before proceeding and throws
`.corruptedHeaderDigest` on a mismatch. The source comment notes that
`SHA-256` is not a secret comparison so short-circuiting `!=` would be
technically fine, but `ConstantTime.equals` is used for consistency.
The spec text above reflects this behaviour.]

### 8.2 HMAC key derivation

The HMAC key for the header is derived from `hmacSeed` using the same
block-key formula used for the HMAC-protected block stream (Section 10),
but with a reserved block index:

    blockKey(index) = SHA-512( UInt64-LE(index) || hmacSeed )
    headerHmacKey   = blockKey( 0xFFFFFFFFFFFFFFFF )

`0xFFFFFFFFFFFFFFFF` (the literal used in the source; equivalently
UInt64 max, all-ones little-endian) is the block index reserved for
the header HMAC. Block indices `0, 1, 2, ...` are reserved for the
HMAC-protected block stream (Section 10).

### 8.3 Verification rule

A reader MUST verify the header HMAC BEFORE invoking the outer cipher
on any subsequent byte. A mismatch MUST be reported as an
authentication error, distinct from the parse-time errors raised by
Sections 1–3. Implementations MUST use a constant-time comparator for
the HMAC tag.

Implementation reference: `HMACProtectedBlockStream.swift` (block key
derivation and `keyForHeader` using the `0xFFFFFFFFFFFFFFFF` literal),
`KDBXReader.swift` (verify-before-decrypt invariant; constant-time
`ConstantTime.equals` used for both `HeaderHash` and `HeaderHMAC`).

## 9. Outer cipher modes

The outer cipher is selected by the `EncryptionAlgorithm` header
record (Section 3.1, ID 2), a 16-byte UUID value.

### 9.1 AES-256-CBC

UUID: `31C1F2E6-BF71-4350-BE58-05216AFC5AFF`

- Key: `mainKey` (Section 7), 32 bytes.
- IV: the `EncryptionNonce` header record (Section 3.1, ID 7), 16 bytes.
- Mode: CBC.
- Padding: PKCS#7. The encrypted payload (HMAC-protected block stream,
  Section 10) is padded; readers MUST validate the padding when
  decrypting.

### 9.2 ChaCha20

UUID: `D6038A2B-8B6F-4CB5-A524-339A31DBB59A`

- Key: `mainKey` (Section 7), 32 bytes.
- Nonce: the `EncryptionNonce` header record, 12 bytes. KDBXKit
  requires exactly 12; readers MUST reject other lengths.
- Counter: starts at 0.
- Variant: IETF ChaCha20 [RFC8439].

### 9.3 Other ciphers

Twofish-CBC has been used by some KeePass distributions historically
and is reserved by the KeePass.info documentation. KDBXKit does NOT
implement Twofish; this specification does not define its parameters.
A reader encountering any UUID outside §9.1 and §9.2 MAY treat the
file as unsupported and abort.

Implementation reference: `AES256CBC.swift`, `Crypto/ChaCha20.swift`,
`KDBXReader.swift` (cipher dispatch).

## 10. HMAC-protected block stream

Immediately following the 32-byte header HMAC tag (Section 8), the
file contains the HMAC-protected block stream that wraps the
ciphertext. The block stream is the outermost authenticated layer of
the payload.

### 10.1 Grammar

    BlockStream = Block* EndBlock
    Block       = HMAC:Byte[32] Length:Int32-LE Payload:Byte[Length]
    EndBlock    = HMAC:Byte[32] Length:Int32-LE = 0

`Length` is the payload size in bytes encoded as a signed 32-bit
little-endian integer. KDBXKit writers cap `Length` at `1_048_576`
(2^20, 1 MiB), matching KeePass's choice. Readers accept any
non-negative value up to `2^31 - 1` for interop. `Payload` is opaque
ciphertext at this layer.

### 10.2 Per-block HMAC

The `hmacSeed` is derived from the master key material (Section 7).
The HMAC key for block `i` (zero-indexed) is:

    blockKey(i) = SHA-512( UInt64-LE(i) || hmacSeed )

where `hmacSeed = SHA-512( masterSalt || unlockKey || 0x01 )`.

The MAC value is:

    HMAC = HMAC-SHA-256( key = blockKey(i),
                         data = UInt64-LE(i) || Int32-LE(Length) || Payload )

Verification is constant-time. The end block (`Length = 0`) carries a
valid HMAC computed over `UInt64-LE(i) || Int32-LE(0)` (empty
payload); KDBXKit writes this HMAC but does not verify it on read —
the reader breaks out of the block loop as soon as it sees
`Length = 0`, before reaching the HMAC-check path.

Block indices `0, 1, 2, …` are reserved for data blocks. Index
`0xFFFFFFFFFFFFFFFF` is reserved for the header HMAC (Section 8) and
MUST NOT appear in this stream.

### 10.3 Block-index sequencing

Block indices are strictly sequential starting at 0. The writer
initialises `blockIndex = 0` and increments it after every emitted
block, including the terminator. The reader mirrors this — it
maintains its own counter starting at 0 and increments after each
verified data block. An out-of-order or replayed block is rejected
implicitly: the HMAC of a block at the wrong position will not match
because the index is bound into both the block key derivation and the
HMAC input.

### 10.4 Decryption boundary

The concatenation of all `Payload` byte runs from index 0 through the
last data block (excluding the end block) is the input to the outer
cipher (Section 9). The cipher operates on the concatenated bytes as
one stream; block boundaries are an authentication-layer concern only.

Implementation reference: `HMACProtectedBlockStream.swift`,
`Streaming/HMACBlockStreamWriter.swift`.

## 11. Optional gzip compression

The plaintext output of the outer cipher (Section 9) MAY be gzip-
compressed before being interpreted as the inner header + inner
payload sequence (Section 12). The `CompressionAlgorithm` header
record (Section 3.1, ID 3) selects:

- `0x00000000` — no compression. The plaintext is consumed as-is.
- `0x00000001` — gzip. The plaintext is an RFC 1952 [RFC1952] gzip
  stream; after gunzip, the decompressed bytes are consumed as the
  inner header + inner payload.

KDBXKit writes with zlib `wBits = 31` (gzip wrapper, maximum 32 KiB
window) and reads with zlib `wBits = 47` (autodetect gzip vs raw zlib;
zlib-only streams MUST NOT be produced and MAY be rejected by other
implementations). A reader implementation MAY use any compliant gzip
decoder; window size is normative as 32 KiB for producers but a
decoder MAY accept larger streams produced by other implementations.

The CRC32 in the gzip trailer is verified by the gzip decoder
itself; the outer HMAC layer (Section 10) already provides
authenticity, so a CRC32 mismatch is reported but never load-bearing
for security.

Other compression values are reserved; readers MUST reject them.
KDBXKit throws `HeaderReader.Error.unsupportedCompression(_:)` on any
unrecognised value — this is a hard error, not a log-and-skip.

Implementation reference: `Streaming/Zlib.swift` (writer and reader
wBits choices and push-based wrapper around system zlib).

## 12. Inner header

The decompressed plaintext (Section 11) begins with the inner header,
followed by the inner payload (Section 14). The inner header is a
sequence of TLV records using the same shape as the outer header but
with a distinct field-ID set and a 4-byte length field that is a
**signed** little-endian 32-bit integer (`Int32-LE`), not `UInt32`.

### 12.1 Grammar

    InnerHeaderRecord = Type:UInt8 Length:Int32-LE Value:Byte[Length]
    InnerHeader       = InnerHeaderRecord+ EndRecord
    EndRecord         = Type:0x00 Length:Int32-LE = 0

The end record's length is zero; there is no `0D0A0D0A` terminator
(unlike the outer header). The end record MUST appear exactly once; no
inner-header record MAY follow it.

Unknown field IDs are silently skipped with a debug-level log entry;
they are NOT a hard error. A reader MUST advance past `Length` bytes
of value data before continuing to the next record, so that the stream
position remains correct after an unknown field.

### 12.2 Defined inner-header records

| ID | Name                | Swift field name       | Value                                                                               |
|----|---------------------|------------------------|-------------------------------------------------------------------------------------|
| 0  | EndOfInnerHeader    | `endOfHeader`          | empty                                                                               |
| 1  | InnerStreamCipherID | `encryptionAlgorithm`  | Int32-LE; see Section 13                                                            |
| 2  | InnerStreamKey      | `encryptionKey`        | ByteArray; key material for the inner stream cipher                                 |
| 3  | Binary              | `binaryContent`        | `Flags:UInt8 Bytes:Byte[Length-1]`; one record per attachment, ordered, zero-indexed |

`InnerStreamCipherID` and `InnerStreamKey` MUST each appear exactly
once. `Binary` records MAY appear zero or more times and define the
binary pool indexed by `<Binary Ref="N"/>` elements in the XML
payload; the first `Binary` record is index 0, the second is index 1,
and so on.

### 12.3 Binary record flags

The first byte of a `Binary` record's value is a flags byte:

    bit 0 (0x01) — protected (memory-protection hint; see below).
    bits 1-7    — reserved; MUST be zero on emit; readers MAY tolerate
                   non-zero values for forward compatibility.

KDBXKit interprets the flags byte with an exact-equality check
(`flags == 0x01`) when setting the `shouldBeProtected` property;
bits 1-7 are therefore currently treated as part of the opaque flags
byte rather than isolated. Writers MUST emit `0x00` (unprotected)
or `0x01` (protected) for this byte.

[Implementation note: The "protected" flag does NOT cause the
binary's bytes to be XOR-masked by the inner stream cipher in
KDBXKit's current implementation. The bytes are stored verbatim
inside the inner header regardless of the flag value. The flag is
treated as an in-process hint that the binary contains sensitive
material (and so should be held in `SecureBytes` or similar while
unlocked). See §13.3 for the keystream consumption order, which
covers protected XML string values only. This may diverge from
other KDBX implementations; cross-implementation behaviour with
respect to this flag is an open question that this specification
does not resolve.]

Implementation reference: `InnerHeaderFieldType.swift`,
`InnerHeader.swift`, `InnerHeaderReader.swift`,
`InnerHeaderWriter.swift`.

## 13. Inner stream cipher

Selected fields inside the XML payload carry sensitive data — entry
passwords by default, plus any custom field with `Protected="True"`.
These values are XOR-masked by a keystream cipher whose ID is given
by the inner-header `InnerStreamCipherID` record (Section 12.2,
field ID 1, Swift name `encryptionAlgorithm`).

### 13.1 Defined cipher IDs

| ID   | Cipher    | Where used        |
|------|-----------|-------------------|
| 0x02 | Salsa20   | KDBX 3.x only     |
| 0x03 | ChaCha20  | KDBX 4.x          |

In KDBXKit these are named enum cases `InnerHeader.EncryptionAlgorithm.Salsa20`
(raw value `2`) and `.ChaCha20` (raw value `3`), stored as `Int32-LE`.

ID `0x00` (no protection) and `0x01` (ArcFour) MUST NOT appear in
KDBX 4.x files; readers MUST reject them with a parse error. KDBXKit
emits only `0x03`.

### 13.2 Key and nonce derivation

The `InnerStreamKey` byte array is taken from inner-header record ID 2
(Swift field `encryptionKey`).

For ChaCha20 (ID `0x03`):

    K   = InnerStreamKey               ; 64 bytes as stored in the inner header
    H   = SHA-512( K )                 ; 64-byte hash
    key   = H[0 .. 31]                 ; first 32 bytes
    nonce = H[32 .. 43]                ; next 12 bytes
    counter = 0

For Salsa20 (ID `0x02`):

    K   = InnerStreamKey               ; 32 bytes as stored in the inner header
    key = SHA-256( K )                 ; 32 bytes
    iv  = E8 30 09 4B 97 20 5D 2A      ; hardcoded 8 bytes (KDBX spec constant)

Implementation reference: `InnerHeader+cryptor.swift` lines 33–68
(eager encryptor/decryptor path) and lines 94–126 (lazy keystream-
source path).

### 13.3 Keystream consumption order

The inner stream cipher masks only **protected XML string values**.
The keystream is consumed in the order in which `Protected="True"`
string nodes are encountered during a depth-first, document-order
traversal of the inner XML payload. Each such node advances the
running keystream position by the byte length of its base64-decoded
ciphertext.

KDBXKit implements this as a random-access façade (`KeystreamSource`)
rather than a stateful sequential cipher. When parsing, the reader
records `(ciphertext, offset, source)` for each protected node — the
offset is the value of a running cursor at the moment the node is
encountered, and the cursor advances by `ciphertext.count` after each
node. Decryption happens lazily on first access, seeking the cipher
to the recorded block and byte offset.

The writer drives the same traversal order as the reader, consuming
the cipher sequentially. As long as both sides visit protected string
nodes in the same document order, the recorded offsets and the
cipher's sequential output agree.

**Inner-header binary pool entries are not XOR-masked by the inner
stream cipher.** The `shouldBeProtected` flag (bit 0 of the flags
byte in a `Binary` record; Section 12.3) is a process-memory
protection hint for client applications, not an on-disk encryption
instruction. Binary data in the inner-header pool is stored
verbatim in both KDBXKit's reader and writer; no keystream bytes are
consumed for binary pool entries.

Note: the claim in Section 12.3 that "Protected binaries are XOR'd
with keystream bytes" reflects the KDBX format specification's stated
intent but does not match KDBXKit's current implementation.
Interoperability against other KDBX clients for the protected-binary
case has not been tested.

Implementation reference: `InnerHeader+cryptor.swift` (key/nonce
derivation), `KeystreamSource.swift` (random-access keystream
interface), `Database/XMLDocumentReader.swift` (cursor advancement
during parse), `Database/XMLDocumentWriter.swift` (sequential
encryption during write), `Crypto/ChaCha20.swift`,
`Crypto/Salsa20.swift`.
