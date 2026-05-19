# The KDBX 4.1 XML Payload

## Abstract

This document specifies the XML document that lives inside the inner
payload of a KDBX 4.x file, after the outer cipher and the inner
header have been processed. It is the companion to
[The KDBX 4.1 Container Format](kdbx-container.md), which specifies
the binary framing; the two together describe the on-disk format
end-to-end.

## Status of This Document

This document is a normative restatement of the inner XML payload
used by KDBX 4.0 and 4.1, cross-checked against the KDBXKit
implementation (<https://github.com/shadone/KDBXKit>) and against
files produced by KeePassXC and the official KeePass 2.x client.
Where this document conflicts with the official KeePass
implementation, the official implementation takes precedence and
this document is in error.

The companion KeePass.info knowledge-base page
<https://keepass.info/help/kb/kdbx.html> remains the upstream source
of intent; this document is byte-precise where that page is
descriptive.

## Conventions

This document inherits the conventions of [the container spec, §
Conventions](kdbx-container.md#conventions):

- RFC 2119 [RFC2119] keywords.
- ABNF [RFC5234] for byte grammars.
- UUIDs in canonical 8-4-4-4-12 form, stored in RFC 4122 byte order
  on disk.
- Hexadecimal byte sequences in uppercase, grouped by 4 bytes,
  separated by single spaces.

Additional conventions specific to the XML payload:

- The XML document is encoded in UTF-8. A `<?xml version="1.0"
  encoding="utf-8"?>` declaration MUST be present as the first
  bytes of the inner payload, before any whitespace.
- Element and attribute names are case-sensitive, written in
  CamelCase, and MUST be matched literally. KDBXKit's reader is
  case-sensitive; producers MUST emit the casing this document
  prescribes.
- Boolean values are encoded as the literal strings `True` and
  `False` (capitalised). `true`/`false` (lower-case) MUST NOT be
  emitted and MAY be rejected on read.
- Empty string values are encoded as `<Element></Element>` (an
  empty element body), not as `<Element/>` (a self-closing tag),
  except for elements whose schema explicitly permits a
  self-closing form. Producers SHOULD emit the open/close form for
  string values to maximise interoperability.
- Whitespace inside element bodies is significant for string
  values that the user typed. Producers MUST NOT add or remove
  whitespace from user-entered string content. Whitespace between
  elements (indentation, newlines) is ignored by parsers and MAY
  be added or removed freely.

## Terminology

The terminology of the container spec applies. Additional terms
specific to the XML payload:

- **KeePassFile** — the root element of the XML document.
- **Meta** — the child of KeePassFile that carries database-wide
  configuration, custom icons, and (in KDBX 3.x) the binary pool.
- **Root** — the child of KeePassFile that carries the Group tree
  and the DeletedObjects sync ledger.
- **Group** — a node in the recursive tree under Root. Holds child
  Groups and child Entries. Has its own UUID and metadata.
- **Entry** — a leaf record holding the user-visible fields
  (Title, UserName, Password, URL, Notes, plus arbitrary custom
  fields), per-entry metadata, attachments, and a history of past
  versions of itself.
- **ProtectedString** — a String value whose ciphertext on disk is
  XOR-masked by the inner stream cipher (container §13) and whose
  in-memory representation MUST keep cleartext out of `Swift.String`
  storage.
- **Binary pool** — the ordered collection of attachment byte
  blobs. In KDBX 4.x the pool lives in the inner header
  (container §12.2, ID 3); entries reference pool entries by
  index. In KDBX 3.1 the pool lives inline in `<Meta><Binaries>`.
- **NullableBoolEx** — a tri-state encoded as the literal strings
  `True`, `False`, or `null` (lower-case). Distinct from a regular
  Bool because the third state means "inherit from the parent
  Group" rather than "unset".

## Document map

1. Document structure (KeePassFile, Meta, Root)
2. Meta element
3. Root element
4. Group element
5. Entry element
6. ProtectedString and the inner stream cipher
7. Binary references and the binary pool
8. Times element and date dialects
9. CustomData and CustomDataItem
10. Dialect notes
11. Appendix A (normative): XML Schema reference
12. Appendix B (normative): Test vectors
13. Appendix C (informative): Parser-warnings catalogue
14. References

## 1. Document structure

The inner payload, after the inner header (container §12), is an XML
document with the following top-level structure:

    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <KeePassFile>
      <Meta> ... </Meta>
      <Root> ... </Root>
    </KeePassFile>

### 1.1 XML declaration

The first bytes of the inner payload MUST be an XML declaration. The
declaration MUST carry `version="1.0"` and SHOULD carry
`encoding="UTF-8"`. KeePassXC's parser rejects documents missing the
`version` attribute, even when an encoding is present; producers MUST
emit both.

KDBXKit emits `standalone="yes"` in addition to the version and
encoding attributes. Consumers MUST ignore unknown declaration
attributes; the `standalone` attribute has no semantic effect on the
inner payload and is included for strict-parser compatibility.

### 1.2 KeePassFile element

`KeePassFile` is the document root. It has no attributes. It contains
exactly two children, in order:

1. `Meta` (exactly 1) — see §2.
2. `Root` (exactly 1) — see §3.

A KDBX 4.x reader MUST reject a document whose root is not
`KeePassFile`, or whose root is missing either child, with a parse
error.

KDBXKit captures unrecognised elements anywhere in the document into
``KDBXContent.parserWarnings`` (a list of strings). Producers MUST
NOT rely on unrecognised elements being preserved on a round-trip —
KDBXKit's reader silently drops them and the writer does not
re-emit. See Appendix C for the catalogue of warnings observed in
the wild.

Implementation reference: `Database/XMLDocumentWriter.swift`
(`KeePassFile` element construction and child ordering),
`Database/XMLDocumentReader.swift`
(`KeePassFile` element check and root dispatch),
`Database/KDBX_XML.xsd` (schema).
