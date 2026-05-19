//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Result of a metadata-only KDBX open. Carries the parsed XML
/// database, header parameters, and per-binary metadata WITHOUT the
/// binary bytes. Bytes are reloaded on demand via
/// `KDBXReader.streamBinary(from:at:into:)` using the retained
/// `source` and `unlockKey`.
///
/// Memory profile at rest: ~the size of the XML state + per-binary
/// metadata (small). The binary payload bytes that would have lived
/// on `innerHeader.binaryContent[i].data` are intentionally not
/// retained.
public struct LazyKDBXContent: Sendable {
    public let database: KDBX
    public let header: Header

    /// Inner header parameters. `innerHeader.binaryContent` is empty
    /// by construction here — use `binaries` for per-attachment
    /// metadata and `KDBXReader.streamBinary(...)` for the bytes.
    /// The cipher params (algorithm + key) ride along so the XML
    /// parser's protected-string keystream can be reconstructed.
    public let innerHeader: InnerHeader

    /// Per-binary metadata, indexed the same as `innerHeader.binaryContent`
    /// would be in an eager parse. Order matches on-disk pool indices.
    public let binaries: [BinaryMetadata]

    public let parserWarnings: [String]

    // Internal — retained for re-stream
    let source: KDBXSource
    let unlockKey: SecureBytes
    let maxDecompressedPayloadSize: Int
}
