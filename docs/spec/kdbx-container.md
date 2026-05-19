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
otherwise. UUID values are stored in the 16-byte big-endian-byte
serialisation used by RFC 4122 [RFC4122], not the Microsoft
mixed-endian guid layout.

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
`Header.swift §FormatVersion` enum.
