# Streaming Attachments

Read and write KDBX vaults whose attachments shouldn't sit in RAM from unlock to lock.

## Overview

The eager path — ``KDBXReader/parse(_:unlockData:)`` + ``KDBXWriter/write(_:unlockData:regenerateSalts:)`` — loads every byte of every attachment into process memory. For a vault with a handful of small attachments that's fine. For a vault carrying photo IDs, scanned documents, or other multi-megabyte binaries, peak memory becomes a problem: you don't want a 200 MB working set every time the user unlocks.

The streaming path keeps binaries on disk and re-streams them on demand.

## When to use it

- Vault total size or attachment-pool size exceeds what you're willing to hold resident.
- You're saving a vault where most binaries haven't changed and shouldn't be paged in just to write them back out.
- You want to extract a single attachment to a file without ever materializing it in `Data`.

If your vault is a few hundred KB total, the eager path is fine — streaming adds complexity without benefit.

## Reading lazily

``KDBXReader/openMetadataOnly(from:unlockData:maxDecompressedPayloadSize:kdfLimits:)`` runs the full decrypt + decompress + inner-header parse + XML parse, then drops the binary bytes. The returned ``LazyKDBXContent`` carries everything needed to re-stream individual binaries on demand. Note its **peak** is still ≈ the full decompressed payload — the whole binary pool is materialized before the bytes are dropped — so it lowers *idle* memory, not the open-time spike.

```swift
let lazy = try KDBXReader.openMetadataOnly(from: .file(url), unlockData: unlock)
// lazy.database — the entry tree
// lazy.header / lazy.innerHeader — vault metadata
// lazy.binaries — [BinaryMetadata] with (offset, length, isProtected, contentHash)
//                  for each attachment in the pool. Bytes are not loaded.
```

When the open-time spike itself must stay bounded (a memory-capped host — e.g. the iOS AutoFill extension under its jetsam limit), use ``KDBXReader/openMetadataStreaming(from:unlockData:maxDecompressedPayloadSize:kdfLimits:)`` instead. It memory-maps the source, decrypts + inflates the block stream incrementally, and hashes + discards each binary payload as it streams — peak ≈ the KDF + XML working set, independent of attachment size. It returns an identical ``LazyKDBXContent`` (4.x only; 3.x throws `unsupportedFormatVersion`).

```swift
let lazy = try KDBXReader.openMetadataStreaming(from: .file(url), unlockData: unlock)
```

``KDBXSource`` is the input abstraction. Use `.file(URL)` for production (the source URL is held for re-streaming); `.data(Data)` is for tests / in-memory.

## Streaming a binary to a destination

``KDBXReader/streamBinary(from:at:into:)`` re-opens the source (memory-mapped) and replays the decrypt + inflate chain, forwarding **only the target binary's** bytes into the supplied ``ByteSink`` and discarding everything else — it stops as soon as the target is complete and reuses the stored unlock key (no KDF re-run), so peak stays at one attachment regardless of vault size.

```swift
var sink = try URLSink(writingTo: destinationURL)
try KDBXReader.streamBinary(from: lazy, at: index, into: &sink)
```

Pick the sink to match the destination:

- ``URLSink`` — straight to a file. No intermediate `Data` allocation.
- ``DataSink`` — accumulate into an in-memory `Data` for general use.
- ``SecureBytesSink`` — mlocked + zero-on-deinit; drain via `takeSecureBytes()`. Use for protected payloads that shouldn't bleed to swap.

## Saving without materializing every binary

``KDBXWriter/streamingWrite(to:content:binaries:unlockData:regenerateSalts:)`` writes a vault file with binaries pulled one at a time from a `[any BinarySource]` array. Mix-and-match between:

- ``LazyBinarySource`` — re-streams from an open ``LazyKDBXContent``. Use this for unchanged attachments still resident on the source vault.
- ``DataBinarySource`` — holds a `Data` directly. Use this for newly-added attachments or for attachments mutated since open.

```swift
let content = KDBXContent(
    database: lazy.database,
    header: lazy.header,
    innerHeader: lazy.innerHeader
)
let binaries: [any BinarySource] = lazy.binaries.indices.map { LazyBinarySource(lazy, at: $0) }
try KDBXWriter.streamingWrite(
    to: destinationURL,
    content: content,
    binaries: binaries,
    unlockData: unlock
)
```

## Memory profile

Peak memory during `streamingWrite` is:

- One attachment's compressed bytes (the largest binary), plus
- ~64 KB gzip working buffer, plus
- ≤16 B AES block buffer, plus
- 1 MB HMAC block buffer

Total: typically `max_binary_size + ~1 MB`. **Independent of total attachment count or total vault size.**

This is the practical benefit: a vault with 500 MB of attachments saves in roughly the same memory footprint as a vault with 5 MB, as long as the individual largest attachment isn't huge.

## Gotchas

- ``LazyKDBXContent`` holds a reference to the source vault. The source URL must remain accessible (and unmodified) for the lifetime of the lazy content and any saves it drives. If the user could delete or rename the file out from under you, capture the bytes into ``KDBXSource/data(_:)`` instead.
- On Apple, ``KDBXSource/file(_:)`` reads via `NSFileCoordinator` to interoperate with iCloud Drive. Don't nest a `.file` read coordinator inside an outer `NSFileCoordinator` write block on the same URL — they deadlock.
- The lazy path is KDBX 4.x only. KDBX 3.1 files store binaries inline in the XML; lazy semantics have no analog. Calling `openMetadataOnly` on a 3.x file throws `KDBXReader.Error.unsupportedFormatVersion(3, _)`; fall back to ``KDBXReader/parse(_:unlockData:)``, observe ``KDBXContent/legacyFormatNotice``, and migrate by saving.
