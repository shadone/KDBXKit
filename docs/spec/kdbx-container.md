# The KDBX 4.1 Container Format

## Abstract

This document specifies the binary container format used by KDBX files
version 4.0 and 4.1, the storage format of the KeePass family of password
managers. It covers the file signature, dynamic header, key derivation,
authenticated encryption, block stream framing, and inner header that
together wrap the encrypted XML payload. The XML payload is specified
in the companion document [The KDBX 4.1 XML Payload](kdbx-xml.md).

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
  consumed by the XML reader. Specified in the companion document
  [The KDBX 4.1 XML Payload](kdbx-xml.md).
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

where `hmacSeed = SHA-512( masterSalt || transformedKey || 0x01 )`.

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

Note: the upstream KDBX format specification's stated intent is that
protected binaries should be XOR-masked with keystream bytes, but this
does not match KDBXKit's current implementation.
Interoperability against other KDBX clients for the protected-binary
case has not been tested.

Implementation reference: `InnerHeader+cryptor.swift` (key/nonce
derivation), `KeystreamSource.swift` (random-access keystream
interface), `Database/XMLDocumentReader.swift` (cursor advancement
during parse), `Database/XMLDocumentWriter.swift` (sequential
encryption during write), `Crypto/ChaCha20.swift`,
`Crypto/Salsa20.swift`.

## 14. Inner payload boundary

The bytes immediately following the inner-header `EndOfInnerHeader`
record are the inner payload. The inner payload is interpreted as an
XML document by the XML reader specified in the companion document
[The KDBX 4.1 XML Payload](kdbx-xml.md).

There is no length prefix on the inner payload. The payload ends at
the end of the decompressed stream (Section 11). The block stream
(Section 10) carries the authoritative end-of-stream sentinel; the
gzip stream's natural end (Section 11) is one layer inside that.

Trailing bytes beyond the close of the outermost XML element are NOT
permitted in KDBX 4.x. KDBXKit passes the entire remaining payload
slice to Foundation's `XMLParser` (libxml2-backed); trailing whitespace
bytes are silently accepted by the underlying parser, while trailing
non-whitespace bytes cause a `.corruptedXML` parse error.

Implementation reference: `KDBXReader.swift` (transition from inner-
header read to XML document construction).

## Appendix A (Informative): KDBX 3.1 read path

KDBX 3.1 differs from 4.x in framing, integrity, and binary storage.
This appendix is informative; KDBXKit reads 3.1 and migrates to 4.1 on
save but never emits 3.x.

### A.1 Header

The 3.x outer header is a TLV sequence with the same record structure
EXCEPT that the length field is `UInt16-LE` (unsigned) rather than
`UInt32-LE`. Additional 3.x-only field IDs:

| ID | Name                  | Value type    | Notes                                              |
|----|-----------------------|---------------|----------------------------------------------------|
| 1  | Comment               | Byte[]        | unused in practice                                 |
| 5  | TransformSeed         | Byte[32]      | AES-KDF seed (no VariantDictionary in 3.x)         |
| 6  | TransformRounds       | UInt64-LE     | AES-KDF rounds                                     |
| 8  | ProtectedStreamKey    | Byte[32]      | Salsa20 key material                               |
| 9  | StreamStartBytes      | Byte[32]      | integrity sentinel (replaced by HMAC in 4.x)       |
| 10 | InnerRandomStreamID   | UInt32-LE     | inner stream cipher ID (Salsa20 = 2)               |

Field IDs 11 (KDFParameters) and 12 (PublicCustomData) MUST NOT
appear in 3.x.

### A.2 Integrity

3.x has no header HMAC. Instead, the first 32 bytes of the decrypted
payload MUST equal `StreamStartBytes`; a mismatch indicates wrong
credentials or a corrupted file. After this 32-byte prefix the
payload is a **hashed block stream**:

    HashedBlock = Index:UInt32-LE Hash:Byte[32] Length:UInt32-LE Payload:Byte[Length]

with `Length == 0` and `Hash` all-zero (conventionally) marking the
end. SHA-256 verifies each block. Block index is informational;
KDBXKit consumes it but does not enforce strict monotonic ordering.

### A.3 Binaries

KDBX 3.1 has no inner header. Binaries live inline in the XML body as
`<Meta><Binaries><Binary ID="N" Compressed="True|False">...base64...</Binary>`
entries; entries reference them via `<Binary Ref="N"/>` in the same
shape as 4.x.

### A.4 Inner stream cipher

Salsa20 only (Section 13). KDBX 3.0 used an ArcFour-derived inner
stream; KDBXKit rejects 3.0 at the version gate
(`KDBXReader.Error.unsupportedFormatVersion(major: 3, minor: 0)`). A
3.1 file that advertises ArcFour (`InnerRandomStreamID = 1`) is also
rejected, surfacing as `.corruptedHeader(reason: "Unsupported inner
random stream ID: 1")`.

### A.5 Migration

KDBXKit upgrades 3.1 to 4.1 on save: AES-KDF parameters are
re-encoded into a VariantDictionary, the binary pool is moved from
the XML body into the inner header, the integrity layer is replaced
by the HMAC block stream, and the inner stream cipher is upgraded to
ChaCha20. The user's master password and key file continue to
authenticate the new file without re-entry.

KDF upgrade is **opt-in**: the library preserves the source AES-KDF
by default. Callers that want to switch to Argon2id (Passie does)
invoke `KDBXContent.upgradeToArgon2id(profile:)` explicitly after
observing `legacyFormatNotice == .willMigrate(from: .v3_1)`.

Implementation reference: `Header3xReader.swift`,
`KDBXReader+Legacy3x.swift`, `HeaderFieldType3x.swift`,
`KDBXContent+upgradeKDF.swift` (KDF migration helper).

---

## Appendix B (Normative): Test vectors

All vectors are reproducible from files in
`KDBXKit/Tests/KDBXKitTests/Resources/`. The xxd offsets are relative
to the start of the named fixture. The byte sequences shown were
captured from the fixture as it exists at the cited commit; if the
fixture is regenerated the vector MUST be regenerated to match.

### B.1 VariantDictionary (Argon2id KDFParameters)

Source: `Tests/KDBXKitTests/Resources/simple-argon2id-aes256.kdbx`,
the `KDFParameters` header record (outer header ID 11, type byte
`0x0B`).

KDFParameters TLV record:

- File offset of type byte: `0x0064` (decimal 100)
- File offset of length field: `0x0065` (decimal 101)
- Length field (UInt32-LE): `8b 00 00 00` = 139 bytes
- File offset of value (start of VariantDictionary): `0x0069` (decimal 105)

Decoded VariantDictionary structure (items in observed emission order):

```
Version            = 00 01                      ; UInt16-LE = 0x0100

Item("$UUID")      Type=0x42  KeyLen=5
                   Key="$UUID"  (24 55 55 49 44)
                   ValueLen=16
                   Value=9e 29 8b 19 56 db 47 73 b2 3d fc 3e c6 f0 a1 e6
                   (Argon2id UUID in RFC 4122 canonical byte order:
                    9E298B19-56DB-4773-B23D-FC3EC6F0A1E6)

Item("I")          Type=0x05  KeyLen=1
                   Key="I"  (49)
                   ValueLen=8
                   Value=0a 00 00 00 00 00 00 00  ; UInt64-LE = 10 (iterations)

Item("M")          Type=0x05  KeyLen=1
                   Key="M"  (4d)
                   ValueLen=8
                   Value=00 00 00 04 00 00 00 00  ; UInt64-LE = 67108864 (64 MiB)

Item("P")          Type=0x04  KeyLen=1
                   Key="P"  (50)
                   ValueLen=4
                   Value=0c 00 00 00              ; UInt32-LE = 12 (parallelism)

Item("S")          Type=0x42  KeyLen=1
                   Key="S"  (53)
                   ValueLen=32
                   Value=14 4c 62 06 ad 60 ea 2b b3 fe 92 52 2a 85 53 b7
                         06 e2 85 96 44 40 f3 0b 7d bf 1d 27 40 5c 81 ef
                   (Argon2 salt — random per fixture)

Item("V")          Type=0x04  KeyLen=1
                   Key="V"  (56)
                   ValueLen=4
                   Value=13 00 00 00              ; UInt32-LE = 0x13 = 19 (Argon2 version 1.3)

Terminator         00
```

**Note on item order**: the fixture emits `$UUID, I, M, P, S, V` —
not the `$UUID, S, V, I, M, P` order that might be inferred from the
KeePass spec. A compliant reader MUST accept items in any order (§4.3).

**Note on `$UUID` encoding**: the 16 UUID bytes appear in RFC 4122
canonical byte order (`9e 29 8b 19 56 db 47 73 b2 3d fc 3e c6 f0 a1 e6`),
which matches the standard string form
`9E298B19-56DB-4773-B23D-FC3EC6F0A1E6` read left-to-right. This is
consistent with the §4.2 convention that UUIDs are stored in canonical
byte order.

Raw bytes of the entire VariantDictionary value field (139 bytes),
as they appear at file offset `0x0069`:

```
00 01 42 05 00 00 00 24 55 55 49 44 10 00 00 00
9e 29 8b 19 56 db 47 73 b2 3d fc 3e c6 f0 a1 e6
05 01 00 00 00 49 08 00 00 00 0a 00 00 00 00 00
00 00 05 01 00 00 00 4d 08 00 00 00 00 00 00 04
00 00 00 00 04 01 00 00 00 50 04 00 00 00 0c 00
00 00 42 01 00 00 00 53 20 00 00 00 14 4c 62 06
ad 60 ea 2b b3 fe 92 52 2a 85 53 b7 06 e2 85 96
44 40 f3 0b 7d bf 1d 27 40 5c 81 ef 04 01 00 00
00 56 04 00 00 00 13 00 00 00 00
```

A round-trip test:

1. Parse the fixture via `KDBXReader.parseHeader`.
2. Re-serialise the resulting `KDFParameters` via
   `toVariantDictionary()` and `VariantDictionaryWriter`.
3. The output byte sequence MUST be byte-identical to the input
   (when `regenerateSalts: false` is used at the writer level).

### B.2 Header HMAC

Source: `simple-argon2id-aes256.kdbx`, password `"123"`.

Outer header TLV records run from file offset 12 through the end of
the `EndOfHeader` value. The byte immediately after that value is the
start of the HeaderHash + HeaderHMAC pair:

```
endOfHeaderOffset = 253 (0x00FD)  ; bytes 12 .. 252 are the header bytes hashed and HMAC'd
```

TLV walk from offset 12 to EndOfHeader:

| FileOffset | Type | TypeName         | Len | ValueOffset |
|------------|------|------------------|-----|-------------|
| 12 (0x000C)  | 0x02 | CipherID         |  16 | 17          |
| 33 (0x0021)  | 0x03 | CompressionFlags |   4 | 38          |
| 42 (0x002A)  | 0x04 | MasterSeed       |  32 | 47          |
| 79 (0x004F)  | 0x07 | EncryptionIV     |  16 | 84          |
| 100 (0x0064) | 0x0B | KdfParameters    | 139 | 105         |
| 244 (0x00F4) | 0x00 | EndOfHeader      |   4 | 249         |

The `EndOfHeader` value is `0D 0A 0D 0A` (4 bytes); it ends at offset
252. `endOfHeaderOffset = 253`.

Observed values in the fixture:

```
HeaderHash  (32 bytes at offset 253)      = 3B 50 87 B0 33 A6 A9 95 95 AD ED 25 8F EA 5A 07
                                            AD E8 99 77 8B 9A 8C 60 F7 09 6E C5 B4 60 D2 00

HeaderHMAC  (32 bytes at offset 285)      = D8 8A E9 42 06 27 7F 0E 8A BE 56 57 64 9E 69 08
                                            89 6D 27 DA 37 F8 E5 26 71 1D 2E 1C EB 02 34 AB
```

Verification recipe:

```
H(password)      = SHA-256( UTF-8("123") )
                 = A6 65 A4 59 20 42 2F 9D 41 7E 48 67 EF DC 4F B8
                   A0 4A 1F 3F FF 1F A0 7E 99 8E 86 F7 F7 A2 7A E3
composite        = SHA-256( H(password) )          ; (no key file)
transformedKey   = Argon2id( password  = composite,
                             salt      = 14 4C 62 06 AD 60 EA 2B B3 FE 92 52
                                         2A 85 53 B7 06 E2 85 96 44 40 F3 0B
                                         7D BF 1D 27 40 5C 81 EF,
                             iterations   = 10,
                             memory       = 65536 KiB,
                             parallelism  = 12,
                             version      = 0x13,
                             outputLen    = 32 )
masterSalt       = DA 94 76 6B 36 43 61 3A 3E B6 F2 A6 EA B1 25 F2
                   B8 F5 F4 BD CF 0D C0 2B D0 E9 4E 9F FF 8A EA 38
hmacSeed         = SHA-512( masterSalt || transformedKey || 0x01 )
headerHmacKey    = SHA-512( UInt64-LE(0xFFFFFFFFFFFFFFFF) || hmacSeed )

Expected HeaderHash = SHA-256( headerBytes )
Expected HeaderHMAC = HMAC-SHA-256( key  = headerHmacKey,
                                    data = headerBytes )
```

Where `headerBytes` is the 241 bytes from file offset 12 through 252
inclusive (the full outer-header TLV sequence including the
`EndOfHeader` record and its `0D 0A 0D 0A` value).

A reader that derives the same `transformedKey` from the same fixture
parameters and password MUST observe these tag values.

### B.3 First data block HMAC

Source: same fixture.

First block fields (at offset `endOfHeaderOffset + 64 = 317`):

```
Block-0 HMAC    (32 bytes at offset 317)  = A3 CF 23 94 73 46 92 0C 2C 34 6D 12 4B 73 61 16
                                            F5 67 8F 9C D8 25 8F 20 76 E8 C2 7B F4 15 F2 22
Block-0 Length  (Int32-LE at offset 349)  = 1792 bytes
Block-0 Payload (first 64 bytes, hex)     = A6 68 C3 38 0B F5 88 76 62 6B 54 3A DA F2 18 7B
                                            46 D0 58 8B AA 55 60 70 7D 8A 15 68 D7 A0 01 0B
                                            BC 46 CB 76 52 C5 F3 46 D9 18 69 B2 5A 7F 7B 2E
                                            47 4C C4 3B 3B 98 59 44 AA 63 97 9E DA 8C CC BE
```

The fixture has a single data block (1792 bytes) followed by a
sentinel block with `Length = 0`.

Verification recipe:

```
block0Key  = SHA-512( UInt64-LE(0) || hmacSeed )
block0Data = UInt64-LE(0) || Int32-LE(1792) || Payload
block0HMAC = HMAC-SHA-256( key = block0Key, data = block0Data )
```

Constant-time tag comparison is REQUIRED (§10.2).

### B.4 Argon2id derivation

Source: `simple-argon2id-aes256.kdbx`.

Inputs:

    password    = "123" (UTF-8 bytes: 31 32 33)
    H(password) = SHA-256( "123" )
                = A665A459 20422F9D 417E4867 EFDC4FB8
                  A04A1F3F FF1FA07E 998E86F7 F7A27AE3
    keyFile     = (absent)
    composite   = SHA-256( H(password) )            ; key file absent → empty contribution
    salt        = 144C6206 AD60EA2B B3FE9252 2A8553B7
                  06E28596 4440F30B 7DBF1D27 405C81EF
    V           = 0x13                              ; Argon2 1.3
    I           = 10
    M           = 67108864                          ; 64 MiB
    P           = 12

Expected:

    transformedKey = Argon2id( password   = composite,
                                salt       = salt,
                                parallelism= 12,
                                memory     = 67108864 bytes,
                                iterations = 10,
                                version    = 0x13,
                                outputLen  = 32 )

The expected 32-byte transformed key MUST match the value computed by
KDBXKit's `Argon2KDF.derive`. A reader that derives the same key from
the same inputs will successfully verify the HeaderHMAC in §B.2 and
unlock the fixture; that end-to-end success is the conformance test
this vector underwrites. The fixture password "123" is fixed at the
test-suite level (see `KeePassXCInteropTests` and
`KDBXKitTests/Resources/`).

## 17. References

### 17.1 Normative

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC4122] Leach, P., Mealling, M., and R. Salz, "A Universally
  Unique IDentifier (UUID) URN Namespace", RFC 4122, July 2005.
- [RFC5234] Crocker, D., Ed., and P. Overell, "Augmented BNF for
  Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- [RFC8439] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF
  Protocols", RFC 8439, June 2018.
- [RFC9106] Biryukov, A., Dinu, D., Khovratovich, D., and S.
  Josefsson, "Argon2 Memory-Hard Function for Password Hashing and
  Proof-of-Work Applications", RFC 9106, September 2021.
- [RFC1952] Deutsch, P., "GZIP file format specification version
  4.3", RFC 1952, May 1996.
- [FIPS180-4] National Institute of Standards and Technology,
  "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.
- [FIPS197] National Institute of Standards and Technology,
  "Advanced Encryption Standard (AES)", FIPS PUB 197, November 2001.

### 17.2 Informative

- KeePass.info knowledge base, "KDBX 4 file format",
  <https://keepass.info/help/kb/kdbx.html>.
- KeePassXC source, <https://github.com/keepassxreboot/keepassxc>.
- KDBXKit, <https://github.com/shadone/KDBXKit>.
- keepassxc-specs (companion document material for the inner XML
  payload), <https://github.com/keepassxreboot/keepassxc-specs>.
