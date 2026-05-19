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

- The XML document is encoded in UTF-8. An `<?xml version="1.0"
  encoding="UTF-8" standalone="yes"?>` declaration MUST be present
  as the first bytes of the inner payload, before any whitespace.
  See §1.1 for normative details.
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
  `True`, `False`, or `Null` (title-case; readers SHOULD also
  accept lower-case `null` for interop — see §4.3). Distinct from a
  regular Bool because the third state means "inherit from the
  parent Group" rather than "unset".

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
[`KDBX_XML.xsd`](KDBX_XML.xsd) (schema).

## 2. Meta element

The Meta element carries database-wide configuration, custom icons,
custom data, and (in KDBX 3.x only) the binary pool. Its children
MAY appear in any order; KDBXKit emits them in the order defined by
`XMLDocumentWriter`. A reader MUST NOT rely on element order.

### 2.1 Defined child elements

| Element                    | Type                      | Cardinality | Since | Notes |
|----------------------------|---------------------------|-------------|-------|-------|
| Generator                  | String                    | 0 or 1      | 4.0   | Writer identifier (e.g. "KeePassXC", "KDBXKit"). Informational. |
| HeaderHash                 | Base64                    | 0 or 1      | 3.1   | KDBX 3.1 only; 4.x readers MUST ignore (the binary header HMAC supersedes it). Stored as a raw Base64 string; Swift type is `String?`. |
| SettingsChanged            | Time                      | 0 or 1      | 4.0   | When any Meta-level setting last changed. See §8 for the date encoding. |
| DatabaseName               | String                    | 0 or 1      | 4.0   | Human-readable vault name. |
| DatabaseNameChanged        | Time                      | 0 or 1      | 4.0   | When `DatabaseName` was last edited. |
| DatabaseDescription        | String                    | 0 or 1      | 4.0   | Free-form vault description. |
| DatabaseDescriptionChanged | Time                      | 0 or 1      | 4.0   | When `DatabaseDescription` was last edited. |
| DefaultUserName            | String                    | 0 or 1      | 4.0   | Pre-fill value for new entries' UserName field. |
| DefaultUserNameChanged     | Time                      | 0 or 1      | 4.0   | When `DefaultUserName` was last edited. |
| MaintenanceHistoryDays     | UInt32                    | 0 or 1      | 4.0   | Days until history entries are deleted in a maintenance pass. |
| Color                      | Color hex                 | 0 or 1      | 4.0   | UI accent color (`#RRGGBB`). Empty string = unset. See §10. |
| MasterKeyChanged           | Time                      | 0 or 1      | 4.0   | Last credential change timestamp. |
| MasterKeyChangeRec         | Int64 (min -1)            | 0 or 1      | 4.0   | Recommended max days before a master-key change; -1 = disabled. Swift: `ValueOrNever<UInt64>`. |
| MasterKeyChangeForce       | Int64 (min -1)            | 0 or 1      | 4.0   | Forced max days before a master-key change; -1 = disabled. Swift: `ValueOrNever<UInt64>`. |
| MasterKeyChangeForceOnce   | Bool                      | 0 or 1      | 4.0   | Force one credential change at the next unlock. |
| MemoryProtection           | MemoryProtectionConfig    | 0 or 1      | 4.0   | Per-field "should be protected in process memory" hints. See §2.2. |
| CustomIcons                | CustomIcon[]              | 0 or 1      | 4.0   | Container; zero or more `<Icon>` children. See §2.3. |
| RecycleBinEnabled          | Bool                      | 0 or 1      | 4.0   | Whether the recycle-bin workflow is active. |
| RecycleBinUUID             | UUID                      | 0 or 1      | 4.0   | UUID of the recycle-bin group; all-zero UUID = create on demand. |
| RecycleBinChanged          | Time                      | 0 or 1      | 4.0   | When the recycle-bin pointer was last changed. |
| EntryTemplatesGroup        | UUID                      | 0 or 1      | 4.0   | UUID of the entry-templates group; all-zero UUID = disabled. |
| EntryTemplatesGroupChanged | Time                      | 0 or 1      | 4.0   | When `EntryTemplatesGroup` was last changed. |
| HistoryMaxItems            | Int32 (min -1)            | 0 or 1      | 4.0   | Max history entries per entry; -1 = unlimited. Swift: `ValueOrUnlimited<UInt32>`. |
| HistoryMaxSize             | Int64 (min -1)            | 0 or 1      | 4.0   | Max estimated in-memory history size in bytes; -1 = unlimited. Swift: `ValueOrUnlimited<UInt64>`. |
| LastSelectedGroup          | UUID                      | 0 or 1      | 4.0   | UI state: which group was selected on last view. |
| LastTopVisibleGroup        | UUID                      | 0 or 1      | 4.0   | UI state: which group was at the top of the tree on last view. |
| Binaries                   | Binary[]                  | 0 or 1      | 3.1   | KDBX 3.1 inline binary pool. KDBXKit reads but never writes this element; 4.x writers MUST NOT emit it (binaries live in the inner header — see container §12.2). |
| CustomData                 | CustomDataWithTimes[]     | 0 or 1      | 4.0   | Vault-level custom key/value items with per-item modification timestamps. See §9. |

### 2.2 MemoryProtection child

`<MemoryProtection>` carries per-default-field flags advising the
application which fields in newly-created entries should be marked
`Protected="True"`. Its children:

| Element         | Type | Default |
|-----------------|------|---------|
| ProtectTitle    | Bool | False   |
| ProtectUserName | Bool | False   |
| ProtectPassword | Bool | True    |
| ProtectURL      | Bool | False   |
| ProtectNotes    | Bool | False   |

These are advisory: the per-entry `Protected` attribute on each
String element (§6) is authoritative for whether a given value's
bytes are XOR-masked by the inner stream cipher. The KDBX spec notes
that KeePass resets these settings to their defaults after opening a
database; treat them as informational hints only.

### 2.3 CustomIcons child

`<CustomIcons>` is a container element holding zero or more `<Icon>`
children. Each `<Icon>` carries:

| Element              | Type    | Cardinality | Since | Notes |
|----------------------|---------|-------------|-------|-------|
| UUID                 | UUID    | 1           | 4.0   | Stable identifier referenced by Group/Entry `CustomIconUUID`. |
| Data                 | Base64  | 1           | 4.0   | Raw icon bytes (PNG, typically; JPEG and ICO also accepted by most clients). |
| Name                 | String  | 0 or 1      | 4.1   | Optional human-readable name. |
| LastModificationTime | Time    | 0 or 1      | 4.1   | When the icon was last edited; used by sync/merge tooling. |

A 4.0 reader MUST ignore `Name` and `LastModificationTime` and MUST
NOT reject a 4.1 file that carries them. A 4.1 writer SHOULD emit
both when the in-memory representation has them.

Implementation reference: `KDBX/Meta.swift`,
`KDBX/MemoryProtectionConfig.swift`, `KDBX/CustomIcon.swift`,
`Database/XMLDocumentReader.swift` (Meta parsing dispatch at
`parseMeta`), `Database/XMLDocumentWriter.swift` (Meta emission
order in `write(_:KDBX.Meta:to:)`).

## 3. Root element

`Root` is the second child of `KeePassFile`. It carries the top-level
Group (and, by recursion, every other Group and Entry in the
database) and a `DeletedObjects` sync ledger.

### 3.1 Children

| Element        | Type            | Cardinality | Notes |
|----------------|-----------------|-------------|-------|
| Group          | Group (§4)      | exactly 1   | The top-level Group. All other Groups and Entries hang off it recursively. |
| DeletedObjects | DeletedObject[] | 0 or 1      | Container for tombstones. See §3.2. |

A reader MUST reject a Root with no top-level Group with a parse
error. If more than one `Group` element appears in `Root`, KDBXKit
silently takes the last one; earlier siblings are overwritten with no
warning recorded in `parserWarnings`. Producers MUST emit exactly one
`Group` child.

KDBXKit places no schema-level constraint on the top-level Group's
Name; convention is to use the database name (often the same string
as `Meta/DatabaseName`).

### 3.2 DeletedObjects (sync ledger)

`DeletedObjects` is a container holding zero or more `DeletedObject`
children:

    <DeletedObjects>
      <DeletedObject>
        <UUID>...</UUID>
        <DeletionTime>...</DeletionTime>
      </DeletedObject>
      ...
    </DeletedObjects>

Each `DeletedObject` has:

| Element      | Type | Cardinality | Notes |
|--------------|------|-------------|-------|
| UUID         | UUID | exactly 1   | The UUID of a Group or Entry that has been deleted. |
| DeletionTime | Time | exactly 1   | When the deletion happened. See §8. |

A reader MUST reject a `DeletedObject` missing either `UUID` or
`DeletionTime` with a parse error. KDBXKit throws
`.corrupted(reason:)` in this case.

The `DeletedObjects` container element itself is optional. When
absent, KDBXKit treats the tombstone list as empty (Swift:
`deletedObjects: []`). The writer omits the `<DeletedObjects>`
element entirely when the list is empty, rather than emitting an
empty container.

The purpose of `DeletedObjects` is to support multi-device sync: a
client that observes a UUID in the live tree on one replica AND in
the `DeletedObjects` of another replica uses the `DeletionTime`
relative to the local last-modified time of the corresponding object
to decide which side wins. KDBXKit preserves tombstones faithfully
across reads and writes; it does not generate tombstones
automatically, and it does not garbage-collect them. Host
applications that perform deletions are responsible for appending a
`DeletedObject` with the deleted item's `uuid` and the current time.

Tombstones MAY accumulate without bound. Implementations MAY
garbage-collect tombstones whose `DeletionTime` is older than some
threshold; a tombstone older than `Meta/MaintenanceHistoryDays` is
one common-but-not-universal choice of threshold. KDBXKit performs
no such collection.

Implementation reference: `KDBX/Root.swift`,
`KDBX/DeletedObject.swift`,
`Database/XMLDocumentReader.swift` (`parseRoot`,
`parseDeletedObjects`, `parseDeletedObject`),
`Database/XMLDocumentWriter.swift` (`write(_:KDBX.Root:to:)`,
`write(_:KDBX.DeletedObject:to:)`).

## 4. Group element

A Group is a node in the hierarchical tree under Root. It carries
its own metadata, optional children (sub-Groups, Entries, or both),
and optional per-Group settings that override database-wide
defaults.

### 4.1 Child elements

| Element                  | Type                      | Cardinality | Since | Notes |
|--------------------------|---------------------------|-------------|-------|-------|
| UUID                     | UUID                      | exactly 1   | 4.0   | Stable identifier. Referenced from DeletedObjects, PreviousParentGroup, and Meta UI-state fields. |
| Name                     | String                    | 0 or 1      | 4.0   | Human-readable label. |
| Notes                    | String                    | 0 or 1      | 4.0   | Free-form text. |
| IconID                   | UInt32                    | exactly 1   | 4.0   | Built-in KeePass icon index. 0..68 are KeePass icons; CustomIconUUID overrides when set. KDBXKit always emits this element (default 0). |
| CustomIconUUID           | UUID                      | 0 or 1      | 4.0   | If set and non-zero, references a `Meta/CustomIcons/Icon/UUID`. All-zero UUID is treated as unset. |
| Times                    | Times (§8)                | 0 or 1      | 4.0   | Per-Group timestamps. |
| IsExpanded               | Bool                      | 0 or 1      | 4.0   | UI state: whether the group node is shown expanded in the client's tree view. |
| DefaultAutoTypeSequence  | String                    | 0 or 1      | 4.0   | Inherited by descendant Entries that do not override. Empty/missing = use the KeePass-default sequence (per Entry §5). |
| EnableAutoType           | NullableBoolEx (§4.3)     | 0 or 1      | 4.0   | Tri-state auto-type policy. `Null` = inherit from parent Group. |
| EnableSearching          | NullableBoolEx (§4.3)     | 0 or 1      | 4.0   | Tri-state search policy. `Null` = inherit from parent Group. |
| LastTopVisibleEntry      | UUID                      | 0 or 1      | 4.0   | UI state: UUID of the entry scrolled to the top on last view. |
| PreviousParentGroup      | UUID                      | 0 or 1      | 4.1   | Set when a group is moved (e.g. to/from Recycle Bin); enables restore-to-original-location. All-zero UUID = none. |
| Tags                     | String                    | 0 or 1      | 4.1   | Comma-separated tag list on write; reader splits on `,` or `;`. See §10. |
| CustomData               | CustomData (§9)           | 0 or 1      | 4.0   | Arbitrary string key/value pairs. No per-item timestamps (contrast with `Meta/CustomData` which uses `CustomDataWithTimes`). |
| Entry                    | Entry (§5)                | 0+          | 4.0   | Child Entries directly inside this Group. |
| Group                    | Group (recursive)         | 0+          | 4.0   | Child sub-Groups. |

### 4.2 Recursion and ordering

Group nesting depth has no schema limit. KDBXKit's parser is a
recursive Swift function (`parseGroup`) that increments a depth
counter on each call. If the counter reaches `maxGroupNestingDepth`
(default: 100) the parser throws `.corrupted(reason:)`. A
pathologically deep file constructed to exceed the call-stack limit
(well above 100) would exhaust the thread stack before this guard
fires; the 100-level cap is a practical safeguard against typical
crafted inputs, not a guarantee against all adversarial depths.

Sibling ordering inside a Group is significant for UI display.
KDBXKit preserves the encountered order on read. The writer emits
children in the in-memory order, and always follows the ordering:
metadata elements (UUID through CustomData), then all Entry
children, then all Group children. Readers MUST NOT rely on a
specific order of metadata elements, but SHOULD preserve Entry /
Group order on round-trip.

### 4.3 NullableBoolEx encoding

`EnableAutoType` and `EnableSearching` carry one of three literal
string values:

| Value   | Meaning |
|---------|---------|
| `True`  | Explicitly enabled for this Group and its descendants. |
| `False` | Explicitly disabled for this Group and its descendants. |
| `Null`  | Inherit from the parent Group. At the root Group, treated as `True`. |

KDBXKit's writer emits the title-case form `Null` (capital N) to
match what KeePass 2 (.NET) produces. The reader accepts both
`Null` and `null` (lower-case n), and `True`/`true`,
`False`/`false`. Any other value causes the reader to throw
`.corrupted(reason:)`.

Note: the Terminology section of this document lists `null`
(lower-case) as the canonical on-disk form. That description
applies to the reader's acceptance set; the writer always emits
`Null` with a capital N.

Implementation reference: `KDBX/Group.swift`,
`KDBX/NullableBoolEx.swift`,
`Database/XMLDocumentReader.swift` (`parseGroup`,
`parseNullableBoolEx`),
`Database/XMLDocumentWriter.swift` (`write(_:KDBX.Group:to:)`).

## 5. Entry element

An Entry is a record holding the user-visible password-manager
fields, optional attachments, an auto-type configuration, and a
history of previous versions of itself. Entries live inside Groups
(§4).

### 5.1 Child elements

| Element             | Type                                  | Cardinality | Since | Notes |
|---------------------|---------------------------------------|-------------|-------|-------|
| UUID                | UUID                                  | exactly 1   | 4.0   | Stable identifier. |
| IconID              | UInt32                                | exactly 1   | 4.0   | Built-in KeePass icon index. KDBXKit always emits this element (default 0). |
| CustomIconUUID      | UUID                                  | 0 or 1      | 4.0   | If set and non-zero, references `Meta/CustomIcons/Icon/UUID`. All-zero UUID is treated as unset. |
| ForegroundColor     | Color (hex string)                    | 0 or 1      | 4.0   | Empty string = unset. See §10. |
| BackgroundColor     | Color (hex string)                    | 0 or 1      | 4.0   | Empty string = unset. See §10. |
| OverrideURL         | String                                | 0 or 1      | 4.0   | Custom URL launcher template (e.g. `cmd://...`). When absent or empty, the entry's standard `URL` field is used. |
| QualityCheck        | Bool                                  | 0 or 1      | 4.1   | Whether KeePass should evaluate Password strength. Absent = inherit host default. |
| Tags                | String (comma-or-semicolon separated) | 0 or 1      | 4.0   | Writer emits `,`-separated; reader splits on either `,` or `;`. See §10. |
| PreviousParentGroup | UUID                                  | 0 or 1      | 4.1   | The Group this Entry was last moved out of (e.g. recycle bin). Used to offer restore-to-original-location affordances. |
| Times               | Times (§8)                            | 0 or 1      | 4.0   | Per-entry timestamps. |
| String              | String entry (§5.2)                   | 0+          | 4.0   | Named field. `Title`, `UserName`, `Password`, `URL`, `Notes` are the five conventional keys. |
| Binary              | Binary entry (§5.3)                   | 0+          | 4.0   | Attachment reference into the binary pool (§7). |
| AutoType            | AutoType config (§5.4)                | 0 or 1      | 4.0   | Per-entry keystroke automation configuration. |
| CustomData          | CustomData (§9)                       | 0 or 1      | 4.0   | Arbitrary string key/value pairs. |
| History             | History container (§5.5)              | 0 or 1      | 4.0   | Previous versions of this entry. |

The writer omits optional elements whose Swift value is `nil` (for
`Optional` fields) or empty (for array fields). The reader treats
absent optional elements as `nil` / empty array without error.

### 5.2 String child elements

A `<String>` element is a named field:

    <String>
      <Key>Title</Key>
      <Value>Bank of Foo</Value>
    </String>

For protected fields the `Value` carries a `Protected="True"`
attribute and a Base64-encoded ciphertext body:

    <String>
      <Key>Password</Key>
      <Value Protected="True">base64-keystream-XOR-cleartext</Value>
    </String>

The five conventional Keys are `Title`, `UserName`, `Password`,
`URL`, and `Notes`. Producers MAY emit additional `<String>` children
with any key. Keys SHOULD be unique within an Entry. KDBXKit's reader
does not enforce uniqueness: duplicate Keys are silently appended to
the `strings` array; `entry.strings` may therefore contain two
elements with the same `key`. Producers MUST NOT emit duplicate Keys.

See §6 for the protected-value encoding.

### 5.3 Binary child elements

A `<Binary>` element references a pool entry:

    <Binary>
      <Key>screenshot.png</Key>
      <Value Ref="0"/>
    </Binary>

`Key` is the filename shown to the user. `Value` is a self-closing
element with a `Ref` attribute whose value is a decimal integer index
into the binary pool (§7). The pool lives in the inner header
(container §12.2, ID 3) for KDBX 4.x, or inline in
`Meta/Binaries` for KDBX 3.1.

### 5.4 AutoType child

`<AutoType>` configures per-entry keystroke automation:

| Element                 | Type               | Cardinality | Notes |
|-------------------------|--------------------|-------------|-------|
| Enabled                 | Bool               | 0 or 1      | Absent or `nil` = inherit from parent Group (`Group/EnableAutoType`). `False` disables AutoType for this entry regardless of the inherited policy. |
| DataTransferObfuscation | Int32              | 0 or 1      | `0` = no obfuscation; `1` = two-channel obfuscation (clipboard + keystrokes). Absent = treat as `0`. |
| DefaultSequence         | String             | 0 or 1      | Overrides the inherited default keystroke sequence. Absent or empty = inherit from `Group/DefaultAutoTypeSequence`. |
| Association             | Association (§5.4) | 0+          | Per-window keystroke overrides, evaluated in order. |

Each `<Association>` has two children, both required:

| Element           | Type   | Notes |
|-------------------|--------|-------|
| Window            | String | Window-title match expression (plain substring or `*`-wildcard). Empty string = match any window. |
| KeystrokeSequence | String | The keystroke sequence to send when this association matches. Empty string = inherit from `DefaultSequence`. |

KDBXKit throws `.corrupted(reason:)` if either `Window` or
`KeystrokeSequence` is missing from an `<Association>`.

### 5.5 History container

`<History>` holds previous versions of this Entry. Each child is a
full `<Entry>` element (same schema as the parent entry) representing
a snapshot taken before the entry was last modified. Snapshots are
ordered oldest-first.

Nested History entries MUST NOT themselves contain a `<History>`
child (history is non-recursive by definition). KDBXKit's reader does
not enforce this constraint: if a nested History entry carries a
`<History>` child, the parser recurses and silently materialises the
inner snapshots into the snapshot's `history` array. Producers MUST
emit flat (non-recursive) History.

`Meta/HistoryMaxItems` (§2.1) caps the number of snapshots retained
per entry; `Meta/HistoryMaxSize` caps the total estimated in-memory
size. Both caps are applied on write.

Implementation reference: `KDBX/Entry.swift`,
`KDBX/AutoType.swift`, `KDBX/ProtectedString.swift`,
`KDBX/ProtectedBinary.swift`,
`Database/XMLDocumentReader.swift` (`parseEntry`,
`parseProtectedString`, `parseProtectedBinary`,
`parseAutoType`, `parseAutoTypeAssociation`,
`parseDataTransferObfuscation`, `parseEntryList`),
`Database/XMLDocumentWriter.swift` (`write(_:KDBX.Entry:to:)`,
`write(_:KDBX.ProtectedString:to:)`,
`write(_:KDBX.ProtectedBinary:to:)`,
`write(_:KDBX.AutoType:to:)`).

## 6. ProtectedString and the inner stream cipher

A `<Value>` element inside a `<String>` (§5.2) MAY carry an attribute
`Protected="True"`. When present, the value's text content is the
**base64-encoded ciphertext** of the cleartext UTF-8 bytes XOR'd
with a slice of the inner-stream keystream. The cipher and key
derivation are specified in container §13; this section specifies
the XML-side mechanics.

### 6.1 Encoded form

A protected value:

    <Value Protected="True">aGVsbG8gd29ybGQ=</Value>

The text content MUST be canonical base64 (RFC 4648 §4). KDBXKit's
writer emits no whitespace inside the body; its reader uses
`Data(base64Encoded:)` without the `.ignoreUnknownCharacters` option
and will reject base64 with embedded whitespace. Producers MUST NOT
emit whitespace inside a protected value's text content.

An empty cleartext MUST be encoded as `<Value Protected="True"></Value>`
(empty body, open/close form). No keystream bytes are consumed for an
empty value. Producers MUST NOT emit `<Value Protected="True"/>` (self-
closing); KDBXKit's writer always emits the open/close form via an
explicit `addText("")` call even when the encrypted result is empty.
KDBXKit's reader treats a self-closing protected value (where no text
node is present) as falling back to an unprotected empty string and
does not advance the keystream cursor — consuming such a node is
correct only because no keystream bytes are needed for an empty
payload, but the fallback path is a reader-side accommodation, not
intended producer behaviour.

### 6.2 XOR encoding

Given:

- `cleartext` — the user's intended UTF-8 byte sequence (length `N`).
- `keystream(offset, length)` — `length` bytes of the inner-stream
  keystream starting at byte `offset` from its initialisation point.
- `offset` — the keystream cursor before this value is processed.

Then:

    ciphertext = cleartext XOR keystream(offset, N)
    valueBody  = base64(ciphertext)
    new cursor = offset + N

The cursor advances by exactly `N` — the byte length of the
**cleartext** (equivalently, the byte length of the base64-decoded
ciphertext). Implementations MUST NOT XOR over surrogate-pair sub-
sequences or normalise the cleartext; the UTF-8 bytes as the user
supplied them are authoritative.

When `N` is zero, no keystream bytes are consumed and the cursor does
not advance. The writer emits an empty base64 body; `Data([]).base64EncodedString()`
yields an empty string, so the serialized form is
`<Value Protected="True"></Value>`.

### 6.3 Keystream consumption order

The keystream is a single global byte sequence consumed across all
protected values in the document. The traversal order is **depth-
first, document order**: as the writer emits the XML payload, it
visits Meta, then Root, then each Group and Entry in source order;
within each Entry, each `<String>` element is visited in document
order; for each protected `<Value>`, the keystream cursor advances
by the cleartext length before the next protected value is processed.

A reader MUST traverse in the same order. KDBXKit's implementation
records `(ciphertext, cursor offset, source)` triples on parse and
defers decryption until each value is read via `.bytes` /
`.withRevealedString` — but the cursor advancement happens in
document order during the parse pass, so the effective order matches
a depth-first traversal.

Implementations MUST NOT skip protected values during traversal
(e.g. for lazy or deferred decode) by advancing the cursor only
when the value is accessed. The cursor position when a given
protected value is parsed MUST equal the sum of cleartext lengths
of all earlier protected values in document order.

History snapshots (§5.5) participate in the same global order: the
writer emits a parent Entry's own `<String>` children first, then
the `<History>` block. Within the History block, each historical
`<Entry>` is written in full (including its own `<String>` children)
in the order the snapshots appear. A `<History><Entry><String><Value
Protected="True">...</Value>` is therefore visited after all of the
parent Entry's own protected values, and after all protected values
in any earlier History snapshot.

### 6.4 Binary content NOT XOR-masked

The `Protected="True"` attribute is defined for `<Value>` inside
`<String>` only. Binary content (`<Binary>` elements, §5.3, and
the binary pool in the inner header — container §12.2, ID 3) is NOT
XOR-masked by the inner stream cipher, even when a pool entry's
inner-header flag bit 0 is set. That flag is a memory-protection
hint only — see container §12.3. KDBXKit's writer never applies the
inner-stream encryptor to binary pool entries, and its reader never
attempts to XOR-unmask them.

### 6.5 In-memory representation (informative)

KDBXKit holds the cleartext bytes of a `ProtectedString.Value` in
`SecureBytes` (mlock'd, zero-on-deinit). Access is via a scoped
callback (`withRevealedString { ... }` or `.bytes`); the cleartext
is not exposed as a `Swift.String` because Swift's String storage
cannot be securely zeroed.

The reader emits `ProtectedString.Value.lazyInnerCipher(ciphertext:
offset: source:)` for every `Protected="True"` node; decryption is
deferred to the first `.bytes` / `.withRevealedString` call. The
writer materialises each value through `.bytes` (running the lazy
decrypt if needed) and re-encrypts with a fresh inner key, because
`KDBXWriter` regenerates all salts — including the inner key — on
every save.

A consumer of this spec writing in a memory-managed language SHOULD
apply equivalent in-process protections: keep cleartext out of
immutable string storage that the GC may copy, zero buffers on free,
and avoid exposing the cleartext via APIs that retain references
beyond the caller's scope.

Implementation reference: `KDBX/ProtectedString.swift`,
`InnerHeader/InnerHeader+cryptor.swift` (cipher construction;
the cipher derivation is specified in container §13),
`InnerHeader/KeystreamSource.swift` (random-access keystream
interface),
`Database/XMLDocumentReader.swift` (`parseProtectedString`,
Protected attribute handling, cursor advancement),
`Database/XMLDocumentWriter.swift` (`write(_:KDBX.ProtectedString:to:)`,
Protected attribute emission and encryptor consumption).

## 7. Binary references and the binary pool

Entry attachments are stored in a **binary pool** outside the XML
document body; each Entry's `<Binary>` child carries a reference into
that pool. The pool's location depends on the format version.

### 7.1 Pool location

- **KDBX 4.x**: the pool lives in the inner header (container
  §12.2, field ID 3). One inner-header `Binary` record per pool
  entry, in pool-index order starting at 0. Each record carries a
  flags byte (memory-protection hint; container §12.3) followed by
  the raw attachment bytes. Pool entries are indexed 0, 1, 2 … in
  declaration order.

- **KDBX 3.x**: the pool lives inline in the XML document, as
  `<Meta><Binaries><Binary ID="N" Compressed="True|False">...
  </Binary></Binaries></Meta>`. The element body is the base64 of
  the attachment bytes, optionally gzip-compressed when
  `Compressed="True"`. Pool indices are the `ID` attribute values
  interpreted as `UInt32`. The reader sorts pool entries by `ID`
  ascending before assigning sequential array indices, so a
  producer MUST use contiguous IDs starting at 0 for the `Ref`
  values in its `<Entry><Binary>` children to resolve correctly.

KDBXKit's reader normalises both layouts into a single in-memory
pool (`InnerHeader.binaryContent`) indexed by integer. The writer
emits only the 4.x inner-header form and never writes a
`<Meta><Binaries>` element.

### 7.2 Entry `<Binary>` child

Inside an Entry (§5):

    <Binary>
      <Key>screenshot.png</Key>
      <Value Ref="0"/>
    </Binary>

| Element | Type     | Notes |
|---------|----------|-------|
| Key     | String   | The user-visible filename. Stored and round-tripped verbatim; KDBXKit's reader and writer do not normalise or strip path-separator characters. |
| Value   | self-closing element with `Ref:UInt32` attribute | The decimal integer pool index. MUST reference an existing pool entry for the file to be considered valid. |

`Ref` is an attribute on `<Value>`, not on `<Binary>` itself.

A `<Value>` element carrying a `Ref` attribute whose value is not a
valid `UInt32` decimal string causes the reader to throw
`.corrupted(reason:)` immediately. A syntactically valid `Ref` that
points beyond the end of the pool does not cause a parse error; it
is surfaced as a structured warning by `KDBXContent.validate()` (a
`ValidationFailure.warning(...)` entry) rather than a thrown error.
Callers that require referential integrity MUST call `validate()`
after parse and treat out-of-range `Ref` values as corrupt.

A single pool entry MAY be referenced by multiple entries
(deduplication). When adding an attachment via the `attach add`
CLI command, KDBXKit checks whether a byte-identical
`InnerHeader.BinaryContent` (same `data` and `shouldBeProtected`)
already exists in the pool and reuses its index rather than
appending a duplicate. The writer itself (both eager
`KDBXWriter.write` and `streamingWrite`) emits the pool as-is from
`innerHeader.binaryContent` without applying any further content-
hash deduplication — deduplication is a write-side concern of the
layer that constructs `KDBXContent`, not of the serialiser.

### 7.3 Compression

In KDBX 4.x there is no per-binary compression flag in the XML. The
inner-header binary record stores the raw attachment bytes; gzip of
the whole inner payload (container §11) provides any compression
benefit.

In KDBX 3.x the `Compressed` attribute on `<Binary>` inside
`<Meta><Binaries>` MAY be `True` (gzip-compressed body) or `False`
(or absent; raw base64). KDBXKit's 3.x reader inflates
`Compressed="True"` entries via `LegacyBinaryDecompressor.gunzip`,
so the in-memory pool always carries the raw (decompressed) payload,
matching the shape the 4.x inner-header pool uses.

### 7.4 In-memory representation

KDBXKit holds binary pool entries in `InnerHeader.BinaryContent`
(`shouldBeProtected: Bool`, `data: Data`). On an eager
`KDBXReader.parse`, every pool entry is materialised into memory at
unlock time. The lazy path (`KDBXReader.openMetadataOnly` +
`streamBinary`) retains only per-binary metadata
(`BinaryMetadata`: offset, length, content hash, protection flag)
and re-streams bytes on demand, so large attachments never need to
be fully resident.

Implementation reference: `KDBX/ProtectedBinary.swift`,
`InnerHeader/InnerHeader.swift` (`BinaryContent` type and pool array),
`InnerHeader/InnerHeaderReader.swift` (inner-header binary record parsing),
`Database/LegacyBinaryDecompressor.swift` (KDBX 3.x inline-pool
gzip decompression),
`Database/XMLDocumentReader.swift` (`parseProtectedBinary` for
entry-side `<Binary>` elements; `parseInlineBinariesPool` for the
3.x `<Meta><Binaries>` pool),
`Database/XMLDocumentWriter.swift` (`write(_:KDBX.ProtectedBinary:to:)`),
`KDBXContent+validate.swift` (out-of-range `Ref` validation),
`KDBXCLICore/Commands/AttachAdd.swift` (content-equality dedup at
attach-add time).

## 8. Times element and date dialects

`<Times>` carries five timestamps for the parent Group or Entry,
plus a boolean expiry flag and a usage counter.

### 8.1 Child elements

| Element              | Swift type | Cardinality | Notes |
|----------------------|------------|-------------|-------|
| CreationTime         | `Date?`    | 0 or 1      | When the entry/group was originally created. |
| LastModificationTime | `Date?`    | 0 or 1      | Updated on any change to the item's fields. |
| LastAccessTime       | `Date?`    | 0 or 1      | Updated on user-visible reads; UI-dependent — treat as a soft hint. |
| ExpiryTime           | `Date?`    | 0 or 1      | Only meaningful when `Expires=True`. |
| Expires              | `Bool?`    | 0 or 1      | If `True`, the parent is considered expired at `ExpiryTime`. |
| UsageCount           | `UInt64?`  | 0 or 1      | Incremented on auto-type or password reveal; updated inconsistently across clients. |
| LocationChanged      | `Date?`    | 0 or 1      | When the parent was last moved within the group tree. Used by sync/merge tools to determine authoritative location. |

All seven children are optional in the XML schema.  KDBXKit's reader
treats a `<Times>` element that is missing any child as that child
being absent rather than as an error.

`LocationChanged` is a child of `<Times>`, not a field on the parent
`<Group>` or `<Entry>` element.  It appears alongside the other six
children and is parsed by the same `parseTimes` routine.

### 8.2 Date dialects

Two date encodings are used, never mixed within a single document:

**KDBX 4.x — seconds-base64.**  The on-wire value is a Base64-encoded
8-byte little-endian `Int64` carrying the number of **whole seconds**
elapsed since `0001-01-01T00:00:00Z` (the .NET `DateTime` epoch,
also known as `DateTime.MinValue`).  The value is rounded to the
nearest second; sub-second precision is not preserved.  The XSD type
`TDateTime` restricts the base type to `xs:base64Binary` with a fixed
length of 8 bytes.

**KDBX 3.x — ISO 8601.**  The on-wire value is an ISO 8601 date-time
string.  The canonical form emitted by KeePass 2 and KeePassXC is
`YYYY-MM-DDTHH:MM:SSZ`.  KDBXKit's reader also accepts fractional
seconds and numeric UTC offsets to tolerate less-canonical producers,
but it converts the result to UTC before storing.

The dialect is selected once at the document level, not per-element.
KDBXKit's `XMLDocumentReader` captures this choice as
`XMLDocumentReader.DateFormat` (`.dotNetTicksBase64` for KDBX 4.x,
`.iso8601` for KDBX 3.x) and passes it at construction time;
thereafter every `<Time>` element in the document is decoded through
the same `parseDate` helper without per-field fallback logic.

The writer (`XMLDocumentWriter`) always emits the 4.x seconds-base64
dialect, consistent with the rule that KDBXKit only ever writes KDBX
4.x files (§ legacy-format migration note in CLAUDE.md).  Producers
MUST NOT mix dialects within a file.

### 8.3 Empty and absent values

An empty `<Time>` element body — e.g.
`<LastAccessTime></LastAccessTime>` — MUST be treated as absent /
unset.  KDBXKit's reader guards on `text(in: child)` returning
non-`nil` before calling `parseDate`, so both an empty element and a
missing element produce `nil` in the `KDBX.Times` struct.  Producers
SHOULD omit the element entirely when the timestamp is unset rather
than emitting an empty element.

### 8.4 Time zones

KDBX timestamps are always UTC.  The seconds-base64 form is an
integer offset from a fixed UTC epoch, so no time-zone qualifier
appears in the encoded value.  The ISO 8601 form MUST carry a
trailing `Z` or an explicit `+00:00` offset; producers MUST NOT emit
local-zone offsets.  A reader receiving a non-UTC ISO 8601 string
MUST convert to UTC before storing the value.  KDBXKit's
`ISO8601DateFormatter` configuration (`withInternetDateTime`) enforces
UTC on parse.

Implementation reference: `KDBX/Times.swift`,
`Extensions/Date+dotnet.swift` (epoch constant and
`secondsSinceDotNetEpoch` / `init(secondsSinceDotNetEpoch:)`
helpers),
`Database/XMLDocumentReader.swift` (`DateFormat` enum, `parseDate`,
`parseTimes`, `parseISO8601`),
`Database/XMLDocumentWriter.swift` (`encode(_:Date)`, `write(_:Times:to:)`),
[`KDBX_XML.xsd`](KDBX_XML.xsd) (`TDateTime` type definition).

## 9. CustomData and CustomDataItem

`<CustomData>` is a free-form key-value container used by
applications and plugins to attach data to a database (on Meta), to
a Group, or to an Entry. KDBXKit and KeePassXC both use it for
non-standard fields that have no first-class home in the schema.

### 9.1 Container

A `<CustomData>` element contains zero or more `<Item>` children.
A `<CustomData>` with no `<Item>` children MAY be emitted as
`<CustomData></CustomData>` or omitted entirely; consumers MUST
treat both equivalently. KDBXKit omits the container element when
the in-memory list is empty.

### 9.2 Item structure

| Element              | Type   | Cardinality | Since | Notes |
|----------------------|--------|-------------|-------|-------|
| `Key`                | String | exactly 1   | 4.0   | Application-defined identifier. Convention: namespace with a prefix (e.g. `passie:vaultID`, `KPXC_BROWSER_<setting>`). |
| `Value`              | String | exactly 1   | 4.0   | The value. Empty body is permitted. |
| `LastModificationTime` | Time | 0 or 1    | 4.1   | When this item was last edited. See §8 for the date encoding. Only present on Meta items; absent on Group and Entry items. |

`Key` and `Value` are both required. KDBXKit's reader skips any
`<Item>` that is missing either element and records a parser
warning; it does not throw.

`LastModificationTime` availability differs by location:

| Location | `LastModificationTime` present? |
|----------|---------------------------------|
| Meta     | Yes (KDBX 4.1+)                 |
| Group    | No                              |
| Entry    | No                              |

A 4.0 reader encountering `LastModificationTime` in a Meta item
MUST ignore it and MUST NOT reject the file. A 4.1 writer SHOULD
emit it whenever the in-memory representation has a value.

### 9.3 Duplicate keys

Keys SHOULD be unique within a single `<CustomData>` container.
KDBXKit's reader builds a plain array: duplicate keys result in
silent append (both items are preserved in document order). No
parse error is raised and the file is not rejected. Producers MUST
enforce uniqueness on emit; the behaviour of a consumer receiving
duplicate keys is implementation-defined.

### 9.4 Conventions

Two soft conventions are widely used:

- **Namespace keys.** Application code MUST namespace its keys to
  avoid collisions. KeePassXC uses prefixes such as `KPXC_` and
  `_LAST_MODIFIED`. KDBXKit host applications use `passie:` for
  Passie-specific keys. The recommended general form is
  `AppName_FieldName` or `vendor:key`.
- **Round-trip preservation.** Implementations MUST preserve
  unknown CustomData items on read-modify-write. KDBXKit reads all
  `<Item>` children into a list and emits them back unchanged, even
  when the host application does not recognise a given key.

### 9.5 Containers by location

The container element name and item element name are identical in
all three locations:

| Location | Container element | Item element |
|----------|-------------------|--------------|
| Meta     | `<CustomData>`    | `<Item>`     |
| Group    | `<CustomData>`    | `<Item>`     |
| Entry    | `<CustomData>`    | `<Item>`     |

The XML shape is the same at all three locations. The only
structural difference is `LastModificationTime` availability (see
§9.2).

Implementation reference: `KDBX/CustomDataItem.swift`,
`KDBX/CustomDataWithTimes.swift`,
`Database/XMLDocumentReader.swift` (`parseCustomDataItemList`,
`parseCustomDataWithTimesList`),
`Database/XMLDocumentWriter.swift` (`write(_:CustomDataItem:to:)`,
`write(_:CustomDataWithTimes:to:)`).

## 10. Dialect notes

This section catalogues real-world divergences between
implementations that the schema does not capture. KDBXKit's
behaviour is tolerant on read and conformant-to-the-XSD on write
unless noted.

### 10.1 Tag separators

The XSD specifies `;` as the tag separator. KeePassXC writes `,` in
practice; KeePass 2.x writes `;`. KDBXKit's reader accepts either
separator (splits on `;` or `,`). KDBXKit's writer emits `,`
(matches KeePassXC's preferred form; both KeePass 2.x and KeePassXC
accept either separator on read).

Tag values containing `;` or `,` cannot be losslessly round-tripped
through any current implementation; producers SHOULD strip these
characters from tag values, or replace them with an escape (none of
the major implementations document an escape, so the practical
recommendation is to disallow them).

### 10.2 Color encoding

`<Color>`, `<ForegroundColor>`, and `<BackgroundColor>` are encoded
as 6-character uppercase hex strings prefixed with `#`, e.g.
`#FF8800`. The format string in source is `"#%02X%02X%02X"`. The
empty string is the canonical "no color" value; KDBXKit's reader
accepts both `<Color></Color>` and absence as "unset", and the
writer omits the element entirely when unset.

The alpha channel is not represented; all KDBX colors are opaque
RGB.

### 10.3 AutoType default sequences

When an Entry's `<AutoType><DefaultSequence>` is empty or missing,
the inherited default sequence applies. Inheritance walks up the
Group tree: each Group has its own `<DefaultAutoTypeSequence>`
(§4); the first non-empty value encountered wins. If no ancestor
sets one, the KeePass built-in default is
`{USERNAME}{TAB}{PASSWORD}{ENTER}`. KDBXKit does not resolve
inheritance on the data layer; that is a UI concern.

### 10.4 NullableBoolEx encoding

KDBXKit's writer emits `Null` (title-case) for the third state.
KeePass 2.x emits `null` (lower-case). KDBXKit's reader accepts
both. Producers MAY emit either; readers MUST accept both. (See
§4.3.)

### 10.5 Boolean encoding

KDBXKit writes `True` / `False` (title-case). KeePass 2.x and
KeePassXC are believed to write the same form. KDBXKit's reader
accepts the title-case form only; lower-case `true`/`false` MAY
be rejected by other implementations. Producers MUST emit
title-case.

### 10.6 UUID encoding inside the XML payload

Inside the XML payload, UUIDs are base64 of the 16 raw bytes in
**canonical RFC 4122 byte order** — the same byte order described
in container §Conventions. A UUID written canonically as
`58F39727-DCA2-4F2D-A6C2-284CFB38E192` appears on disk as
`58 F3 97 27 DC A2 4F 2D A6 C2 28 4C FB 38 E1 92`, which base64-
encodes to `WPOXJ9yiTy2mwihM+zjhkg==`. This matches the on-disk
encoding used for the container-level UUIDs (KDF, cipher).

An empty body and a UUID of all-zero bytes are treated as
equivalent by KDBXKit's reader; both decode to the nil UUID
(`00000000-0000-0000-0000-000000000000`).

[Implementation note: KDBXKit's Swift `UUID` values are held with
a byte-reversed `uuid_t` tuple internally (see
`Extensions/UUID+uint128.swift`,
`Extensions/Data+asUUIDLE.swift`); the writer's
`toUInt128().toDataLittleEndian().base64EncodedString()` chain
and the reader's `asUUIDLE()` reverse this internal
representation back into canonical RFC 4122 bytes on the wire.
This is the same internal-only convention noted in container §6
for KDF UUIDs and does not affect the wire format described
above.]

### 10.7 Whitespace and indentation

KDBXKit's writer emits indented XML using a tab character (`\t`)
per depth level. KeePassXC also uses tab indentation. All readers
MUST ignore inter-element whitespace. Producers MAY emit
unindented XML; in-element whitespace is significant only for
string values (see the Conventions section).

### 10.8 Element ordering inside Meta

Meta's child elements MAY appear in any order; KDBXKit emits them
in the order shown in §2's table. KeePassXC emits a similar but
not byte-identical order. Round-trip stability through
`KDBXReader.parse` + `KDBXWriter.write` with `regenerateSalts:
false` holds for `KDBXKit`-to-`KDBXKit` round-trips; cross-
implementation round-trips re-serialise to the local writer's
element order and are NOT byte-stable at the XML level.

Implementation reference: `KDBX/Color.swift`,
`Database/XMLDocumentReader.swift`,
`Database/XMLDocumentWriter.swift`,
`Extensions/Data+asUUIDLE.swift`,
`Extensions/UUID+uint128.swift`,
`KDBXKit/CLAUDE.md §Format dialects we round-trip`.

## Appendix A (Normative): XML Schema reference

The canonical XML schema for KDBX 4.x lives alongside this
document at [`KDBX_XML.xsd`](KDBX_XML.xsd). That file is the
authoritative reference for element names, attribute names,
cardinalities, and value types. It is copyright (C) 2007-2025
Dominik Reichl and is published at
<https://keepass.info/help/kb/kdbx.html>. This appendix does not
reproduce the XSD; instead it notes where real-world files diverge
from what the XSD declares, and lists the elements that were added
in KDBX 4.1.

### A.1 Permissive cardinalities

The XSD declares the `Meta` children using `xs:all` with
`minOccurs="0"` on every child element. A reader MUST tolerate any
missing optional element by treating it as unset, not by rejecting
the document.

`TGroup` and `TEntry` are declared as `xs:sequence`. The XSD
itself carries an inline comment on both types: "this is actually
unordered except for the Entry and Group child elements, where the
order matters." A reader MUST NOT rely on a fixed order of metadata
children within a Group or Entry; only the relative order of sibling
Entry and Group elements within a parent Group is significant.

### A.2 Real-world divergences

The XSD does not fully capture the following dialect variations
(cf. §10):

| Topic | XSD says | Real-world fact |
|---|---|---|
| Tag separator | `Tags` content type is `xs:string`; XSD documentation says `;` | KeePassXC writes `,`-separated; KeePass 2.x writes `;`-separated. Readers MUST accept either separator. |
| NullableBoolEx | `TNullableBoolEx` enumerates `Null`, `null`, `False`, `false`, `True`, `true` | The XSD already enumerates both casings. Writers SHOULD emit title-case (`Null`, `True`, `False`); readers MUST accept both. |
| Child element order | `TGroup` and `TEntry` are `xs:sequence` | XSD comments acknowledge the sequence is notionally unordered for metadata children; KeePassXC and KeePass 2.x emit differing orders. Readers MUST NOT rely on order. |
| XML declaration encoding attribute | Schema is silent on the declaration | KDBXKit writes `encoding="UTF-8"` (uppercase); Foundation's `XMLParser` is case-insensitive on the encoding attribute. Readers MUST be case-insensitive here. |
| Color pattern | `TColor` restricts to `#[0-9A-F]{6}` (uppercase hex digits only) | KeePassXC may emit lowercase hex (`#ff8800`). Readers SHOULD accept lowercase; producers SHOULD emit uppercase to match the schema. |

### A.3 Validation in practice

KDBXKit does NOT validate parsed XML against the XSD at runtime;
the schema is checked in for reference and for offline tooling
(e.g. generating type bindings, validating test fixtures during
development). Producers SHOULD validate output against the schema
before shipping a new fixture file. Readers MUST NOT assume that
input is schema-valid.

`KDBXContent.parserWarnings` accumulates silently-dropped elements
and attributes encountered during parse (see §1.2). When adding a
fixture produced by a third-party client, asserting
`parserWarnings == []` is the recommended way to catch schema
extensions that KDBXKit does not yet model.

### A.4 Schema versioning

The bundled XSD is authored against KDBX 4.1 (its header comment
reads "KDBX 4.1 XML Schema"). It covers both KDBX 4.0 and 4.1
payloads because all 4.1 additions are declared with
`minOccurs="0"`, making them optional for a 4.0-only producer
without invalidating the schema for a 4.1 producer.

The 4.1 additions relative to 4.0 are:

| Location | Added element | Notes |
|---|---|---|
| `Meta/CustomIcons/Icon` | `Name` | Optional human-readable icon name. |
| `Meta/CustomIcons/Icon` | `LastModificationTime` | When the icon was last edited. |
| `Meta/CustomData/Item` | `LastModificationTime` | Per-item modification timestamp on vault-level custom data. Not present on Group or Entry custom data. |
| `Group` | `PreviousParentGroup` | UUID of the group's previous parent; enables recycle-bin restore. |
| `Group` | `Tags` | Semicolon-separated tag list per the XSD; in practice comma-separated on write (see §A.2). |
| `Entry` | `QualityCheck` | Whether KeePass should evaluate the entry's password strength. |
| `Entry` | `PreviousParentGroup` | UUID of the entry's previous parent group. |

Note: `Entry/OverrideURL` and `Entry/Tags` are present in the XSD
as fields on `TEntry` but were already present in KDBX 4.0; they
are not 4.1 additions.

A 4.0-only reader MUST tolerate the presence of all elements listed
above by ignoring them; it MUST NOT reject a 4.1 file that carries
them.

There is no version attribute on the XML document itself. The KDBX
format version is determined entirely by the binary container header
(container §2); the shape of the XML payload follows from that
binary-level version. Readers determine which 4.1 additions to
expect by inspecting the binary header's major/minor version fields,
not by probing for the presence of 4.1 elements in the XML.

## Appendix B (Normative): Test vectors

All vectors are reproducible from fixtures in
`KDBXKit/Tests/KDBXKitTests/Resources/`. The XML fragments are
quoted verbatim from the named files (decrypted form). Element
ordering and whitespace reflect the producer's actual output, not
the canonical form prescribed by this document — see §10.7 and
§10.8 for producer-vs-consumer expectations.

For encrypted `.kdbx` fixtures the decrypted XML can be obtained
with:

```
KDBX_PASSWORD=123 swift run kdbx db xml <fixture>.kdbx
```

All `kpxc-*` fixtures use the password `123`; `kpxc-extras.kdbx`
uses `test`.

---

### B.1 Minimal database structure

**Source:** `Tests/KDBXKitTests/Resources/database-encrypted-empty.xml`
(pre-decrypted; produced by KeePassXC, KDBX 4.1).
This file is the smallest well-formed `KeePassFile` document with
no entries: a single root `<Group>` containing no children and an
empty `<DeletedObjects/>` element.

See §3 for the top-level structure and §4.1 for group fields.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<KeePassFile>
	<Meta>
		<Generator>KeePassXC</Generator>
		<DatabaseName>test3</DatabaseName>
		<DatabaseNameChanged>CurE3w4AAAA=</DatabaseNameChanged>
		<DatabaseDescription/>
		<DatabaseDescriptionChanged>COrE3w4AAAA=</DatabaseDescriptionChanged>
		<DefaultUserName/>
		<DefaultUserNameChanged>COrE3w4AAAA=</DefaultUserNameChanged>
		<MaintenanceHistoryDays>365</MaintenanceHistoryDays>
		<Color/>
		<MasterKeyChanged>NerE3w4AAAA=</MasterKeyChanged>
		<MasterKeyChangeRec>-1</MasterKeyChangeRec>
		<MasterKeyChangeForce>-1</MasterKeyChangeForce>
		<MemoryProtection>
			<ProtectTitle>False</ProtectTitle>
			<ProtectUserName>False</ProtectUserName>
			<ProtectPassword>True</ProtectPassword>
			<ProtectURL>False</ProtectURL>
			<ProtectNotes>False</ProtectNotes>
		</MemoryProtection>
		<CustomIcons/>
		<RecycleBinEnabled>True</RecycleBinEnabled>
		<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
		<RecycleBinChanged>COrE3w4AAAA=</RecycleBinChanged>
		<EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
		<EntryTemplatesGroupChanged>COrE3w4AAAA=</EntryTemplatesGroupChanged>
		<LastSelectedGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastSelectedGroup>
		<LastTopVisibleGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleGroup>
		<HistoryMaxItems>10</HistoryMaxItems>
		<HistoryMaxSize>6291456</HistoryMaxSize>
		<SettingsChanged>cBHF3w4AAAA=</SettingsChanged>
		<!-- CustomData omitted for brevity -->
	</Meta>
	<Root>
		<Group>
			<UUID>yNCyIsK0RECvhzYeNr8gNg==</UUID>
			<Name>Root</Name>
			<Notes/>
			<IconID>48</IconID>
			<Times>
				<LastModificationTime>COrE3w4AAAA=</LastModificationTime>
				<CreationTime>COrE3w4AAAA=</CreationTime>
				<LastAccessTime>COrE3w4AAAA=</LastAccessTime>
				<ExpiryTime>COrE3w4AAAA=</ExpiryTime>
				<Expires>False</Expires>
				<UsageCount>0</UsageCount>
				<LocationChanged>COrE3w4AAAA=</LocationChanged>
			</Times>
			<IsExpanded>True</IsExpanded>
			<DefaultAutoTypeSequence/>
			<EnableAutoType>null</EnableAutoType>
			<EnableSearching>null</EnableSearching>
			<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
		</Group>
		<DeletedObjects/>
	</Root>
</KeePassFile>
```

Key observations:
- `<RecycleBinUUID>` is the nil UUID (`AAAA…AA==`, 16 zero bytes)
  because no recycle bin group has been created yet (§2.1).
- `<EnableAutoType>null</EnableAutoType>` and
  `<EnableSearching>null</EnableSearching>` carry the literal string
  `null` to signal "inherit from parent" (§4.1).
- `<DeletedObjects/>` is self-closing; a consumer MUST treat an
  absent element and a self-closing element identically (§3.2).

---

### B.2 Entry with the five standard strings

**Source:** `Tests/KDBXKitTests/Resources/simple-argon2id-aes256.xml`
(pre-decrypted; produced by KeePassXC, KDBX 4.1, Argon2id + AES-256-CBC).
The database has exactly one entry. The `<Password>` value is
protected (keystream-encrypted and Base64-encoded); the remaining
four strings are stored in the clear.

See §5 for the full entry schema and §6 for the protected-string
mechanism.

```xml
<Entry>
	<UUID>pU2GYYk8SpiT/CeWYClPFw==</UUID>
	<IconID>0</IconID>
	<ForegroundColor/>
	<BackgroundColor/>
	<OverrideURL/>
	<Tags/>
	<Times>
		<LastModificationTime>PenE3w4AAAA=</LastModificationTime>
		<CreationTime>J+nE3w4AAAA=</CreationTime>
		<LastAccessTime>PenE3w4AAAA=</LastAccessTime>
		<ExpiryTime>J+nE3w4AAAA=</ExpiryTime>
		<Expires>False</Expires>
		<UsageCount>0</UsageCount>
		<LocationChanged>PenE3w4AAAA=</LocationChanged>
	</Times>
	<String>
		<Key>Notes</Key>
		<Value/>
	</String>
	<String>
		<Key>Password</Key>
		<Value Protected="True">pVXQV6Re1DQe2w==</Value>
	</String>
	<String>
		<Key>Title</Key>
		<Value>hello</Value>
	</String>
	<String>
		<Key>URL</Key>
		<Value>https://example.org</Value>
	</String>
	<String>
		<Key>UserName</Key>
		<Value>myusername</Value>
	</String>
	<AutoType>
		<Enabled>True</Enabled>
		<DataTransferObfuscation>0</DataTransferObfuscation>
		<DefaultSequence/>
	</AutoType>
	<History/>
</Entry>
```

Key observations:
- The five standard keys appear in alphabetical order here because
  KeePassXC emits them that way; the spec does not mandate any
  particular order (§5.2).
- `<Notes>` has an empty `<Value/>` rather than being omitted.
  Consumers MUST treat an absent `<String>` for a standard key the
  same as one with an empty value (§5.2).
- `<History/>` is self-closing, meaning zero history snapshots
  (§5.5).

---

### B.3 Protected vs unprotected string values

**Source:** `Tests/KDBXKitTests/Resources/simple-argon2id-aes256.xml`
(same file as B.2).

The two `<String>` elements below appear consecutively in the file.
`Password` carries `Protected="True"`; `Title` does not.

See §6 for the full protected-string mechanism.

```xml
	<String>
		<Key>Password</Key>
		<Value Protected="True">pVXQV6Re1DQe2w==</Value>
	</String>
	<String>
		<Key>Title</Key>
		<Value>hello</Value>
	</String>
```

**Keystream cursor:** The Password value `pVXQV6Re1DQe2w==` decodes
to 10 bytes. Because this is the first protected value in the
document, the keystream cursor is at offset 0 before decryption and
advances to offset 10 after. The Title string does not carry
`Protected="True"`, so it does not advance the cursor.

The cleartext of `pVXQV6Re1DQe2w==` is the entry's password; the
actual cleartext depends on the inner random stream key derived from
this specific file's inner header (§6.1). A consumer verifying
this vector must:
1. Derive the inner random stream key from the inner header of
   `simple-argon2id-aes256.kdbx`.
2. Initialise the ChaCha20 keystream (inner stream ID `3`) at
   offset 0.
3. XOR the 10 decoded bytes against the first 10 keystream bytes to
   recover the cleartext password.

---

### B.4 Group recursion

**Source:** `Tests/KDBXKitTests/Resources/kpxc-deep-groups.kdbx`
(KDBX 4.1; decrypt with password `123`).
The fixture contains the Root group, one entry at the root level,
and a sub-group `L1` which in turn contains a sub-group `L2` (and
so on, ten levels deep). The fragment below shows Root > L1 > L2,
truncated to demonstrate the recursive pattern.

See §4 for group nesting rules and §4.2 for sibling order
(KeePassXC places entries before sub-groups within a group).

```xml
<Group>
	<UUID>WPOXJ9yiTy2mwihM+zjhkg==</UUID>
	<Name>Root</Name>
	<!-- Times and other fields omitted for brevity -->
	<Entry>
		<UUID>pU2GYYk8SpiT/CeWYClPFw==</UUID>
		<!-- Entry fields omitted for brevity -->
	</Entry>
	<Group>
		<UUID>RohyLCpgTUiNF6ZXi/FhlQ==</UUID>
		<Name>L1</Name>
		<Notes/>
		<IconID>48</IconID>
		<Times>
			<LastModificationTime>5D+a4Q4AAAA=</LastModificationTime>
			<CreationTime>5D+a4Q4AAAA=</CreationTime>
			<LastAccessTime>5D+a4Q4AAAA=</LastAccessTime>
			<ExpiryTime>5D+a4Q4AAAA=</ExpiryTime>
			<Expires>False</Expires>
			<UsageCount>0</UsageCount>
			<LocationChanged>5D+a4Q4AAAA=</LocationChanged>
		</Times>
		<IsExpanded>True</IsExpanded>
		<DefaultAutoTypeSequence/>
		<EnableAutoType>null</EnableAutoType>
		<EnableSearching>null</EnableSearching>
		<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
		<Group>
			<UUID>t71/zMo4RrK1hn47UGT8vg==</UUID>
			<Name>L2</Name>
			<Notes/>
			<IconID>48</IconID>
			<Times>
				<LastModificationTime>5D+a4Q4AAAA=</LastModificationTime>
				<CreationTime>5D+a4Q4AAAA=</CreationTime>
				<LastAccessTime>5D+a4Q4AAAA=</LastAccessTime>
				<ExpiryTime>5D+a4Q4AAAA=</ExpiryTime>
				<Expires>False</Expires>
				<UsageCount>0</UsageCount>
				<LocationChanged>5D+a4Q4AAAA=</LocationChanged>
			</Times>
			<IsExpanded>True</IsExpanded>
			<DefaultAutoTypeSequence/>
			<EnableAutoType>null</EnableAutoType>
			<EnableSearching>null</EnableSearching>
			<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
			<!-- L3 … L10 follow the same pattern, each nested one level deeper -->
		</Group>
	</Group>
</Group>
```

Key observations:
- The `<Entry>` child appears before the `<Group>` child within
  Root. This is the sibling order KeePassXC uses (entries before
  sub-groups); KDBXKit preserves and emits the same order on
  round-trip (§4.2).
- Each group carries its own `<Times>` block. Sub-groups do not
  inherit timestamps from their parent.
- `<EnableAutoType>null</EnableAutoType>` propagates to all nested
  groups created without an explicit override.

---

### B.5 DeletedObjects tombstone

**Source:** Derived from
`Tests/KDBXKitTests/Resources/simple-argon2id-aes256.kdbx`
by running:

```
cp simple-argon2id-aes256.kdbx /tmp/test-with-deleted.kdbx
KDBX_PASSWORD=123 swift run kdbx entry rm \
    /tmp/test-with-deleted.kdbx --path /hello --permanent
```

The `--permanent` flag hard-deletes the entry and records a
`<DeletedObject>` sync entry instead of moving it to a recycle-bin
group. The resulting `<DeletedObjects>` block is:

```xml
	<DeletedObjects>
		<DeletedObject>
			<UUID>pU2GYYk8SpiT/CeWYClPFw==</UUID>
			<DeletionTime>d3+h4Q4AAAA=</DeletionTime>
		</DeletedObject>
	</DeletedObjects>
```

The `<UUID>` matches the entry UUID from B.2, confirming that the
tombstone references the deleted object's original UUID. The
`<DeletionTime>` is encoded in the standard .NET-ticks-Base64
format (§8.2). On sync merge, a compliant consumer uses this
tombstone to identify and remove the object from a peer replica
that still carries it (§3.2).

Key observations:
- An entry moved to the recycle-bin group (soft delete) does NOT
  produce a `<DeletedObject>`; tombstones are recorded only on
  permanent (hard) deletion and on sync-merge of hard-deleted items.
- The `<DeletedObjects>` element is always present in a well-formed
  document; when there are no tombstones it appears as
  `<DeletedObjects/>` (self-closing), as seen in B.1.

---

## Appendix C (Informative): Parser-warnings catalogue

This appendix lists XML elements and attributes that KDBXKit's
reader does not fully model. Encountering one of these does NOT
produce a parse error; the reader appends a string to
`KDBXContent.parserWarnings` and the unrecognised element or
attribute is silently dropped from the in-memory representation.
On round-trip the dropped item is NOT re-emitted.

This appendix is informative. Producers writing for KeePass /
KeePassXC compatibility SHOULD NOT emit elements that KDBXKit
drops, since the round-trip would lose data. Readers implementing
the spec from scratch MAY choose to model these elements; KDBXKit
does not, and the rationale for each is given below.

### C.1 Format of a parser warning

Each warning is a free-form `String`. The conventions KDBXKit
follows internally are:

    "Unexpected element <FullyQualifiedPath>"
    "Unexpected attribute '<name>' in <ElementName> in <FullyQualifiedPath>"
    "Unexpected attribute value '<value>' in attribute <name> in <FullyQualifiedPath>"
    "Missing Key or Value node in CustomDataWithTimes in <FullyQualifiedPath>"
    "Negative value '<n>' for unsigned field in <FullyQualifiedPath>; dropping"
    "Failed to parse <Type> '<text>' in <FullyQualifiedPath>; dropping"
    "Protect in memory not yet implemented in <FullyQualifiedPath>"
    "Unexpected Protected value '<value>' in Binary in <FullyQualifiedPath>"

`<FullyQualifiedPath>` is produced by the XML node's
`fullyQualifiedName` property and takes the form
`KeePassFile/Meta/MemoryProtection/UnknownField`, giving the
exact position in the document tree.

Producers MUST NOT rely on the exact warning string format; it is
not part of the public API and may change without notice.

### C.2 Known dropped elements

The table below maps each `record(...)` call site in
`XMLDocumentReader.swift` to the document context where it can
fire. The call-site count (excluding the `record` function
definition itself) is **32**.

#### C.2.1 Unknown children of `KeePassFile`

Any direct child of `<KeePassFile>` other than `<Meta>` and
`<Root>` triggers:

    "Unexpected element: KeePassFile/<ElementName>"

No real-world producer is known to emit extra top-level children;
this guard exists as a safety net.

#### C.2.2 Unknown children of `Meta`

Any direct child of `<Meta>` not listed in §2 triggers:

    "Unexpected element KeePassFile/Meta/<ElementName>"

Typical real-world source: a future KeePass / KeePassXC release
adds a new `<Meta>` field (e.g. `<DatabaseTags>`) before KDBXKit
models it.

#### C.2.3 Unknown children of `MemoryProtection`

Any child of `<Meta><MemoryProtection>` other than `ProtectTitle`,
`ProtectUserName`, `ProtectPassword`, `ProtectURL`, and
`ProtectNotes` triggers:

    "Unexpected element KeePassFile/Meta/MemoryProtection/<ElementName>"

KeePass 2.x does not emit extra children here. This guard is
forward-compatibility protection.

#### C.2.4 Unknown children of `CustomIcons`

Any child of `<Meta><CustomIcons>` other than `<Icon>` triggers:

    "Unexpected element KeePassFile/Meta/CustomIcons/<ElementName>"

The expected children are zero or more `<Icon>` items; anything
else is dropped.

#### C.2.5 Unknown children of a `CustomIcon`

Any child of an `<Icon>` element other than `UUID`, `Data`,
`Name`, and `LastModificationTime` triggers:

    "Unexpected element KeePassFile/Meta/CustomIcons/Icon/<ElementName>"

The `Name` and `LastModificationTime` fields were added in KDBX
4.1 (§2.3); a 4.0 file omits them without a warning.

#### C.2.6 Unknown children of `CustomData` item lists

Two distinct parsers handle `<CustomData>` blocks: one for
`<Meta><CustomData>` (items carry `LastModificationTime`) and one
for group/entry `<CustomData>` (plain key/value pairs).

Any child of the `<CustomData>` container other than `<Item>`
triggers:

    "Unexpected element <path>/CustomData/<ElementName>"

Any child of an `<Item>` element other than `Key`, `Value`, and
(where applicable) `LastModificationTime` triggers:

    "Unexpected element <path>/CustomData/Item/<ElementName>"

If an `<Item>` element is missing either its `<Key>` or `<Value>`
child the item is dropped and a warning is emitted:

    "Missing Key or Value node in CustomDataWithTimes in <path>/CustomData/Item"

This warning fires for both the timed and the plain variants of the
item parser.

#### C.2.7 Unknown children of `Root`

Any child of `<Root>` other than `<Group>` and `<DeletedObjects>`
triggers:

    "Unexpected element KeePassFile/Root/<ElementName>"

#### C.2.8 Unknown children of `Group`

Any child of a `<Group>` element not listed in §4.1 triggers:

    "Unexpected element <path>/Group/<ElementName>"

This is the most likely source of real-world warnings: KeePassXC
and other clients have added group-level fields (e.g. an extra
metadata element) in incremental releases before the spec
absorbed them.

#### C.2.9 Unknown children of `Times`

Any child of a `<Times>` block other than `CreationTime`,
`LastModificationTime`, `LastAccessTime`, `ExpiryTime`, `Expires`,
`UsageCount`, and `LocationChanged` triggers:

    "Unexpected element <path>/Times/<ElementName>"

`<Times>` appears under both `<Group>` and `<Entry>`.

#### C.2.10 Unknown children of `Entry`

Any child of an `<Entry>` element not listed in §5.1 triggers:

    "Unexpected element <path>/Entry/<ElementName>"

Like §C.2.8, this is a forward-compatibility guard.

#### C.2.11 Unknown children of `History`

Any child of `<Entry><History>` other than `<Entry>` triggers:

    "Unexpected element <path>/Entry/History/<ElementName>"

History snapshot entries are themselves `<Entry>` elements; any
other tag is unexpected.

#### C.2.12 Unknown children of `AutoType`

Any child of `<AutoType>` other than `Enabled`,
`DataTransferObfuscation`, `DefaultSequence`, and `Association`
triggers:

    "Unexpected element <path>/Entry/AutoType/<ElementName>"

#### C.2.13 Unknown children of `AutoType/Association`

Any child of an `<Association>` block other than `<Window>` and
`<KeystrokeSequence>` triggers:

    "Unexpected element <path>/Entry/AutoType/Association/<ElementName>"

#### C.2.14 Attributes on `String/Value`

`<String><Value>` accepts two attributes: `Protected` and
`ProtectInMemory`. An attribute with any other name triggers:

    "Unexpected attribute '<name>' in String in <path>/Entry/String/Value"

A value of `Protected` or `ProtectInMemory` that is neither `True`
nor `False` triggers:

    "Unexpected attribute value '<value>' in attribute <name> in <path>/Entry/String/Value"

#### C.2.15 `ProtectInMemory="True"` on `String/Value` (not yet implemented)

When `<Value ProtectInMemory="True">` is encountered, KDBXKit
records:

    "Protect in memory not yet implemented in <path>/Entry/String"

and falls back to `ProtectedString.Value.protectedInMemory(_:)`.
The value is stored in the in-memory model but is not re-emitted as
`ProtectInMemory="True"` by the writer — it round-trips as an
ordinary unprotected string. This is an implementation limitation,
not a parse failure.

#### C.2.16 Unknown children of `Entry/Binary` (protected-binary child list)

Any child of the `<Binary>` element inside `<Entry>` other than
`<Key>` and `<Value>` triggers:

    "Unexpected element <path>/Entry/Binary/<ElementName>"

#### C.2.17 Attributes on `Entry/Binary/Value`

`<Binary><Value>` accepts two attributes: `Ref` and `Protected`.
An attribute with any other name triggers:

    "Unexpected attribute '<name>' in Binary in <path>/Entry/Binary/Value"

A value of the `Protected` attribute that is neither `true`, `True`,
`false`, nor `False` (case-insensitive) triggers:

    "Unexpected Protected value '<value>' in Binary in <path>/Entry/Binary/Value"

#### C.2.18 Unknown children of `DeletedObjects`

Any child of `<DeletedObjects>` other than `<DeletedObject>`
triggers:

    "Unexpected element KeePassFile/Root/DeletedObjects/<ElementName>"

#### C.2.19 Unknown children of `DeletedObject`

Any child of a `<DeletedObject>` element other than `<UUID>` and
`<DeletionTime>` triggers:

    "Unexpected element <path>/DeletedObjects/DeletedObject/<ElementName>"

#### C.2.20 Malformed unsigned integers (lenient path)

Two fields — `MaintenanceHistoryDays` and `Times/UsageCount` — use
a lenient parser that tolerates bad input rather than aborting the
parse. A negative decimal string in either of these fields triggers:

    "Negative value '<n>' for unsigned field in <path>/<FieldName>; dropping"

A string that cannot be parsed as the target integer type at all
triggers:

    "Failed to parse <Type> '<text>' in <path>/<FieldName>; dropping"

In both cases the field is set to `nil` in the in-memory model
(the property is optional) and parsing continues.

#### C.2.21 Unknown children and unknown attributes of `Meta/Binaries/Binary` (KDBX 3.x only)

`<Meta><Binaries>` is a KDBX 3.x-only inline binary pool (§10).
Any child of the `<Binaries>` container other than `<Binary>`
triggers:

    "Unexpected element KeePassFile/Meta/Binaries/<ElementName>"

Any attribute on a `<Binary>` element other than `ID`, `Compressed`,
and `Protected` triggers:

    "Unexpected attribute '<name>' in Binary in KeePassFile/Meta/Binaries/Binary"

These warnings are only reachable when parsing a 3.x file; a
well-formed KDBX 4.x file does not contain `<Meta><Binaries>`.

### C.3 Adding new fixtures

When adding a third-party fixture to
`Tests/KDBXKitTests/Resources/`, the convention (per
`KDBXKit/CLAUDE.md`) is to assert
`KDBXContent.parserWarnings == []` to catch features that are not
modelled. If the assertion fails, the choice is:

- **Model the feature in KDBXKit** — changes the source but
  preserves full fidelity.
- **Scrub the unrecognised element from the fixture** — loses
  fidelity but keeps the test focused on what KDBXKit covers.

Both are legitimate; the assertion exists to make the choice
explicit rather than silent.

## 14. References

### 14.1 Normative

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC4122] Leach, P., Mealling, M., and R. Salz, "A Universally
  Unique IDentifier (UUID) URN Namespace", RFC 4122, July 2005.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.
- [RFC5234] Crocker, D., Ed., and P. Overell, "Augmented BNF for
  Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- [W3C-XML] Bray, T., et al., "Extensible Markup Language (XML)
  1.0 (Fifth Edition)", W3C Recommendation, November 2008,
  <https://www.w3.org/TR/xml/>.

The KDBX container specification (this document's companion) is
also normative:

- [KDBX-Container] Dzyubenko, D., "The KDBX 4.1 Container Format",
  KDBXKit `docs/spec/kdbx-container.md`.

### 14.2 Informative

- KeePass.info knowledge base, "KDBX 4 file format",
  <https://keepass.info/help/kb/kdbx.html>.
- KeePass.info knowledge base, "Key files",
  <https://keepass.info/help/base/keys.html>.
- KeePassXC source, <https://github.com/keepassxreboot/keepassxc>.
- KDBXKit, <https://github.com/shadone/KDBXKit>.
- keepassxc-specs (earlier informal XML reference document),
  <https://github.com/keepassxreboot/keepassxc-specs>.
