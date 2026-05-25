# Error Handling

Working with KDBXKit's typed error enums.

## Overview

KDBXKit doesn't crash on malformed input, wrong credentials, or unsupported features — every failure mode is a typed enum case with a doc comment explaining when it fires. The two main error surfaces are ``KDBXReader/Error`` (for reads) and ``KDBXWriter/Error`` (for writes); credential derivation has its own ``UnlockDataError``.

Each enum is exhaustive: you can pattern-match on it without a catch-all, and adding a new case is a breaking API change you'll see during compile.

## Reading

The common cases when calling ``KDBXReader/parse(_:unlockData:)``:

```swift
do {
    let content = try KDBXReader.parse(data, unlockData: unlock)
    // …
} catch KDBXReader.Error.wrongCredentials {
    // User-typed password or key file was wrong. Show a retry prompt.
} catch KDBXReader.Error.unsupportedFormatVersion(let major, let minor) {
    // File is KDBX \(major).\(minor) — outside our supported range.
    // KDBXKit reads 3.1, 4.0, 4.1. Anything else is rejected here.
} catch KDBXReader.Error.unsupportedKDF(let uuid) {
    // KDF UUID we don't implement.
} catch KDBXReader.Error.corruptedHMAC(let reason) {
    // Outer-stream integrity check failed. File is tampered or truncated.
} catch KDBXReader.Error.corruptedHeader(let reason) {
    // Header parse failed, or KDF rejected its own parameters.
} catch KDBXReader.Error.corruptedInnerHeader(let reason) {
    // Post-decrypt inner-header parse failed.
} catch KDBXReader.Error.corruptedXML(let reason) {
    // Post-decompress XML parse failed.
} catch KDBXReader.Error.decompressedPayloadTooLarge(let limit) {
    // Inflated payload exceeded the cap (default 256 MB). Crafted "zip bomb"
    // territory; legitimate vaults never trigger this.
} catch KDBXReader.Error.invalidFileSignature {
    // Magic bytes don't match — not a KDBX file at all.
}
```

For a complete listing of every case and its doc comment, see ``KDBXReader/Error``.

## Writing

``KDBXWriter/Error`` follows the same shape. The most useful cases:

```swift
do {
    let bytes = try KDBXWriter().write(content, unlockData: unlock)
    try bytes.write(to: url)
} catch KDBXWriter.Error.unsupportedKDF(let uuid) {
    // Content carries a KDF we can't write.
} catch KDBXWriter.Error.encryptionFailed(let reason) {
    // Crypto step refused — usually means KDF rejected parameters or the
    // inner cipher's key-derivation step failed.
} catch KDBXWriter.Error.compressionFailed(let reason) {
    // gzip output step failed. Practically never on legitimate input.
} catch KDBXWriter.Error.xmlSerializationFailed(let reason) {
    // The XML writer rejected something it built from the content tree —
    // usually a programmer-error path (an invalid string slipped in).
}
```

## Credential derivation

``UnlockDataError`` is the inner error for credential → unlock key derivation. The reader and writer wrap it into their own enums, so application code typically catches ``KDBXReader/Error`` rather than this — but it's surfaced directly if you call ``UnlockData/computeUnlockKey(kdfParameters:limits:)`` (used by callers timing the KDF for UI feedback).

```swift
let kdfStart = Date.now
do {
    _ = try unlock.computeUnlockKey(kdfParameters: header.kdfParameters)
} catch UnlockDataError.unsupportedKDF(let uuid) {
    // Configured KDF isn't implemented by KDBXKit.
} catch UnlockDataError.kdfFailed(let reason) {
    // KDF rejected the parameters in the header. Usually means a crafted
    // file or a parameter-validator mismatch.
}
let elapsed = Date.now.timeIntervalSince(kdfStart)
```

## Mapping to UI

For a typical password-manager UI, the cases group into three buckets:

| Reader case | What to show the user |
|---|---|
| `wrongCredentials` | "Incorrect password. Try again." |
| `unsupportedFormatVersion`, `unsupportedKDF`, `unsupportedEncryption`, `unsupportedCompression` | "This vault uses a feature we don't support." Include version / UUID for diagnostics. |
| `corruptedHMAC`, `corruptedHeader`, `corruptedHeaderDigest`, `corruptedInnerHeader`, `corruptedXML`, `invalidFileSignature` | "This file appears damaged." Offer to back up before further attempts. |
| `decompressedPayloadTooLarge`, `kdfParametersOutOfRange` | "This file appears damaged or malicious." Same UI as corruption. |
| `unlockDataRequired` | Programmer error — you forgot to pass credentials. Crash in debug. |
| `unexpectedEOF` | "This file appears truncated." |

## Diagnostics

After a failed parse, the mutating-`reader` form gives access to whatever was decoded before the failure:

```swift
var reader = KDBXReader(data)
do {
    _ = try reader.parse(unlockData: unlock)
} catch {
    // reader.header is whatever parsed before the failure (nil for early
    // failures, populated for post-header failures). Useful for logging.
    print(reader.header?.formatVersion ?? "no header read")
    throw error
}
```

For richer diagnostics — e.g., retaining the decrypted XML so a wrong-cipher bug can be diagnosed against the plaintext — pass `retainsXMLForDiagnostics: true`. **Don't** use this in production: it keeps the cleartext XML payload resident for the reader's lifetime.
