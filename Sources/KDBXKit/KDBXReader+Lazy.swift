//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// Lazy / streaming variants of `KDBXReader.parse`. The eager `parse`
/// produces a `KDBXContent` with every binary's bytes resident on
/// `innerHeader.binaryContent[i].data`. The lazy variants here
/// produce a `LazyKDBXContent` whose `binaries` array carries only
/// metadata (size, isProtected, contentHash, offset/length) and
/// reload bytes from the underlying source on demand.
///
/// Use-case: password manager vaults that hold many large attachments
/// (recovery PDFs, SSH keys, identity scans). Eager parse keeps every
/// byte in RAM for the lifetime of the unlocked vault; lazy lets RAM
/// usage stay at ~XML + metadata.
public extension KDBXReader {
    /// Open a KDBX file in metadata-only mode. Runs the full
    /// decrypt + decompress + parse pipeline ONCE, captures
    /// per-binary metadata + content hashes, then drops the binary
    /// bytes before returning. The result keeps a reference to
    /// `source` and the derived `unlockKey` so individual binaries
    /// can be re-streamed via `streamBinary(...)`.
    ///
    /// Peak memory during this call: ~the decompressed payload size
    /// (binary bytes + XML). After return: metadata + XML state only.
    ///
    /// - important: KDBX 3.x files cannot be opened in metadata-only
    ///   mode. The 3.x on-disk layout stores binaries inline in the
    ///   decompressed XML body, not in an inner-header pool that
    ///   `streamBinary` could re-slice. Lazy / streaming semantics
    ///   would have to materialize every binary anyway. Calls on a
    ///   3.x source throw ``KDBXReader/Error/unsupportedFormatVersion(major:minor:)``
    ///   with `major == 3`. Callers should fall back to
    ///   ``KDBXReader/parse(_:unlockData:)``, observe
    ///   ``KDBXContent/legacyFormatNotice``, and prompt the user to
    ///   save (which migrates the file to 4.1).
    static func openMetadataOnly(
        from source: KDBXSource,
        unlockData: UnlockData,
        maxDecompressedPayloadSize: Int = KDBXReader.maxDecompressedPayloadSize,
        kdfLimits: KDFParameterLimits = .default
    ) throws -> LazyKDBXContent {
        let clock = ContinuousClock()
        let readStart = clock.now
        let encrypted = try source.readAll()
        KDBXLog.perf.debug("openMetadataOnly: read file (\(encrypted.count) bytes) — \((clock.now - readStart).kdbxLoggedMilliseconds)ms")

        let cryptoStart = clock.now
        let decrypted = try decryptAndDecompress(
            encrypted,
            unlockData: unlockData,
            maxDecompressedPayloadSize: maxDecompressedPayloadSize,
            kdfLimits: kdfLimits
        )
        KDBXLog.perf.debug("openMetadataOnly: KDF + decrypt + decompress — \((clock.now - cryptoStart).kdbxLoggedMilliseconds)ms")

        // Parse inner header in metadata mode — captures offsets +
        // hashes for every binary, returns InnerHeader with empty
        // binaryContent.
        let parseStart = clock.now
        let innerHeaderResult: (header: InnerHeader, binaries: [BinaryMetadata], length: Int)
        do {
            var reader = InnerHeaderReader(data: decrypted.payload)
            innerHeaderResult = try reader.parseMetadata()
        } catch {
            switch error {
            case let .corrupted(reason):
                throw KDBXReader.Error.corruptedInnerHeader(reason: reason)
            case .unexpectedEOF:
                throw KDBXReader.Error.unexpectedEOF
            }
        }
        KDBXLog.perf.debug("openMetadataOnly: inner-header parse (\(innerHeaderResult.binaries.count) binaries) — \((clock.now - parseStart).kdbxLoggedMilliseconds)ms")

        // Extract XML — everything after the inner header up to EOF.
        let xmlBytes = decrypted.payload.suffix(from: decrypted.payload.startIndex + innerHeaderResult.length)
        guard let xmlDocument = String(validating: xmlBytes, as: UTF8.self) else {
            throw KDBXReader.Error.corruptedXML(reason: "Failed to parse the XML document as a utf8 string")
        }

        let database: KDBX
        var parserWarnings: [String] = []
        let keystreamSource: KeystreamSource
        do {
            keystreamSource = try innerHeaderResult.header.makeKeystreamSource()
        } catch {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Inner-stream key derivation failed: \(error)")
        }
        let xmlStart = clock.now
        do {
            let xmlDocumentReader = try XMLDocumentReader(
                xmlDocument: xmlDocument,
                keystreamSource: keystreamSource
            )
            database = try xmlDocumentReader.parse()
            parserWarnings = xmlDocumentReader.collectedWarnings
        } catch {
            switch error {
            case let .corrupted(reason):
                throw KDBXReader.Error.corruptedXML(reason: reason)
            }
        }
        KDBXLog.perf.debug("openMetadataOnly: XML parse (\(xmlDocument.count) chars) — \((clock.now - xmlStart).kdbxLoggedMilliseconds)ms")

        // `decrypted.payload` goes out of scope here — binary bytes
        // and XML buffer are released. The returned LazyKDBXContent
        // holds only metadata + parsed XML state.
        return LazyKDBXContent(
            database: database,
            header: decrypted.header,
            innerHeader: innerHeaderResult.header,
            binaries: innerHeaderResult.binaries,
            parserWarnings: parserWarnings,
            source: source,
            unlockKey: decrypted.unlockKey,
            maxDecompressedPayloadSize: maxDecompressedPayloadSize
        )
    }

    /// Re-stream the bytes for one binary into `sink`. Reopens the
    /// source (memory-mapped), replays decrypt + inflate, and forwards
    /// **only the target binary's** bytes to the sink — every other
    /// byte (the rest of the pool, the XML) is discarded as it streams,
    /// and the block loop stops the moment the target is complete.
    ///
    /// Peak memory is the sink's choice (a ``SecureBytesSink`` page, a
    /// ``URLSink`` file write) plus a small pipeline window — independent
    /// of total vault / attachment size. After return: nothing retained.
    /// The stored unlock key + header are reused, so there is no KDF
    /// re-run on this path.
    ///
    /// - important: To resolve more than one binary — e.g. when
    ///   rebuilding the pool for a save — do NOT call this in a loop:
    ///   each call replays the decrypt from the start, so resolving the
    ///   whole pool that way is O(binaries × file_size). Use
    ///   ``withDecryptedBinaries(from:_:)`` instead, which pays the
    ///   decrypt cost once for any number of binaries.
    ///
    /// `sink` is mutated and finalized by this call.
    static func streamBinary(
        from lazy: LazyKDBXContent,
        at index: Int,
        into sink: inout some ByteSink
    ) throws {
        guard lazy.binaries.indices.contains(index) else {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Binary index out of range: \(index)")
        }

        // Map the file (clean pages excluded from phys_footprint) and
        // build the same decrypt → inflate chain the metadata open uses,
        // terminating in an extractor that keeps only binary `index`.
        let encrypted = try lazy.source.readAll(mappedIfSafe: true)
        let payloadPos = try payloadStart(in: encrypted)
        let mainContentKey = MainKey.make(masterSalt: lazy.header.masterSalt, unlockKey: lazy.unlockKey)

        var localSink = sink
        defer { sink = localSink }
        let extractor = StreamingBinaryExtractor(targetIndex: index) { buf in
            try localSink.write(buf)
        }
        let downstream: any StreamingByteConsumer
        switch lazy.header.compressionAlgorithm {
        case .none:
            downstream = extractor
        case .gzip:
            downstream = try StreamingInflateReader(
                downstream: extractor,
                maxOutputBytes: lazy.maxDecompressedPayloadSize
            )
        }
        let decryptor = try DecryptingStreamReader(
            header: lazy.header,
            mainKey: mainContentKey,
            downstream: downstream
        )

        // ZlibError is internal — map decompression failures to the same
        // public typed errors the eager path surfaces.
        do {
            let stoppedEarly = try driveHMACBlocks(
                encrypted,
                from: payloadPos,
                masterSalt: lazy.header.masterSalt,
                unlockKey: lazy.unlockKey,
                into: decryptor,
                stopEarly: { extractor.done }
            )
            // Only when the stream ran to completion without an early stop
            // (target not found — index beyond the on-disk pool) does the
            // chain need finalizing; the found case always stops early.
            if !stoppedEarly {
                try decryptor.finalize()
            }
        } catch ZlibError.outputTooLarge {
            throw KDBXReader.Error.decompressedPayloadTooLarge(limit: lazy.maxDecompressedPayloadSize)
        } catch let error as ZlibError {
            throw KDBXReader.Error.corruptedXML(reason: "Failed to decompress: \(error)")
        }
        try localSink.finalize()

        guard extractor.found else {
            // In range per captured metadata, yet absent from the stream:
            // the on-disk pool diverged from what `openMetadata*` recorded.
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Binary \(index) not found in inner stream")
        }
    }

    /// Decrypt + decompress the source ONCE, then hand `body` a
    /// `resolve` closure that slices any binary out of the resident
    /// payload by pool index. Use this — not a loop over
    /// ``streamBinary(from:at:into:)`` — whenever more than one binary
    /// is needed (rebuilding the binary pool for a save, exporting all
    /// attachments, …): the single-binary API replays the full-file
    /// decrypt on every call, so resolving the whole pool that way is
    /// O(binaries × file_size). This pays the decrypt cost a single
    /// time regardless of how many binaries `body` asks for.
    ///
    /// `resolve(index)` returns a `Data` that is a view onto the
    /// single decrypted buffer (no per-binary copy); retaining one
    /// keeps that buffer alive. It throws
    /// ``KDBXReader/Error/corruptedInnerHeader(reason:)`` for an
    /// out-of-range or out-of-bounds index, mirroring `streamBinary`.
    ///
    /// Peak memory during the call: ~the decompressed payload size,
    /// the same as a single `streamBinary`. The decrypted payload is
    /// released when the last `Data` handed out by `resolve` is
    /// released (after return, that is whatever `body` kept).
    static func withDecryptedBinaries<R>(
        from lazy: LazyKDBXContent,
        _ body: (_ resolve: (_ index: Int) throws -> Data) throws -> R
    ) throws -> R {
        let decrypted = try decryptWholePayload(of: lazy)
        let binaries = lazy.binaries
        return try body { index in
            try binarySlice(at: index, in: decrypted.payload, binaries: binaries)
        }
    }

    /// Read + decrypt + decompress the lazy source's whole payload.
    /// Shared by `streamBinary`, `withDecryptedBinaries`, and
    /// `LazyBinaryCache`.
    internal static func decryptWholePayload(
        of lazy: LazyKDBXContent
    ) throws -> DecryptedKDBXPayload {
        // Map rather than copy: clean file-backed pages are excluded from
        // phys_footprint, so the encrypted bytes don't scale the peak even
        // though the decompressed payload below still materializes in full.
        // (`streamBinary` uses the per-binary streaming extractor instead;
        // this whole-payload path backs the multi-binary `withDecryptedBinaries`
        // batch, where one decrypt amortizes across the whole pool.)
        let encrypted = try lazy.source.readAll(mappedIfSafe: true)
        return try decryptAndDecompressUsing(
            encrypted,
            unlockKey: lazy.unlockKey,
            header: lazy.header,
            maxDecompressedPayloadSize: lazy.maxDecompressedPayloadSize
        )
    }

    /// Slice one binary out of an already-decrypted payload. The
    /// returned `Data` is a view onto `payload`; it shares storage.
    internal static func binarySlice(
        at index: Int,
        in payload: Data,
        binaries: [BinaryMetadata]
    ) throws -> Data {
        guard binaries.indices.contains(index) else {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Binary index out of range: \(index)")
        }
        let meta = binaries[index]
        let start = payload.startIndex + meta.decompressedOffset
        let end = start + meta.decompressedLength
        guard end <= payload.endIndex else {
            throw KDBXReader.Error.corruptedInnerHeader(
                reason: "Binary slice [\(meta.decompressedOffset)..<\(end)] exceeds payload bounds"
            )
        }
        return payload[start..<end]
    }
}

// MARK: - Internal pipeline helpers

struct DecryptedKDBXPayload {
    let header: Header
    let unlockKey: SecureBytes
    /// Decrypted + decompressed bytes — inner header followed by XML.
    let payload: Data
}

extension KDBXReader {
    /// Runs steps 1..4.a.i of the KDBX read pipeline: parse cleartext
    /// header, verify digests, derive unlock key, decrypt block
    /// stream, decompress. Stops just before inner-header parsing so
    /// both the eager (`parse`) and lazy (`openMetadataOnly`) paths
    /// can share the work.
    static func decryptAndDecompress(
        _ data: Data,
        unlockData: UnlockData,
        maxDecompressedPayloadSize: Int,
        kdfLimits: KDFParameterLimits
    ) throws -> DecryptedKDBXPayload {
        var reader = KDBXReader(data)
        // 1. Header
        let header: Header
        let headerLength: Int
        do {
            var headerReader = HeaderReader(data: data)
            (header, headerLength) = try headerReader.parse()
        } catch {
            switch error {
            case .invalidSignature:
                throw KDBXReader.Error.invalidFileSignature
            case let .unsupportedFormatVersion(major, minor):
                throw KDBXReader.Error.unsupportedFormatVersion(major: major, minor: minor)
            case let .unsupportedCompression(compression):
                throw KDBXReader.Error.unsupportedCompression(compression)
            case let .unsupportedEncryption(uuid):
                throw KDBXReader.Error.unsupportedEncryption(uuid)
            case let .corrupted(reason):
                throw KDBXReader.Error.corruptedHeader(reason: reason)
            case .unexpectedEOF:
                throw KDBXReader.Error.unexpectedEOF
            }
        }
        reader.cursor.advance(by: headerLength)

        // 2. SHA-256 of header
        let headerData = Data(data[..<headerLength])
        let headerSHA256 = headerData.sha256()
        let headerSHA256FromFile = try reader.readDataPublic(length: 32)
        if !ConstantTime.equals(headerSHA256, headerSHA256FromFile) {
            throw KDBXReader.Error.corruptedHeaderDigest
        }

        // 3. HMAC-SHA256 of header
        // Time the KDF in isolation — it dominates open cost for
        // high-iteration vaults and is the usual answer to "why is unlock
        // slow". Measured inline (not via a closure helper) so the typed
        // `UnlockDataError` throw still propagates unwrapped.
        let kdfClock = ContinuousClock()
        let kdfStart = kdfClock.now
        let unlockKey: SecureBytes
        do throws(UnlockDataError) {
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: header.kdfParameters, limits: kdfLimits)
        } catch {
            switch error {
            case let .unsupportedKDF(uuid):
                throw KDBXReader.Error.unsupportedKDF(uuid)
            case let .kdfFailed(reason):
                throw KDBXReader.Error.corruptedHeader(reason: "KDF rejected header parameters: \(reason)")
            case let .unsupportedKDFParameter(name):
                throw KDBXReader.Error.corruptedHeader(reason: "Unsupported KDF parameter: \(name)")
            case let .kdfParametersOutOfRange(reason):
                throw KDBXReader.Error.kdfParametersOutOfRange(reason: reason)
            }
        }
        KDBXLog.perf.debug("decryptAndDecompress: KDF [\(header.kdfParameters.perfSummary)] — \((kdfClock.now - kdfStart).kdbxLoggedMilliseconds)ms")
        let headerKey = HMACProtectedBlockStream.keyForHeader(masterSalt: header.masterSalt, unlockKey: unlockKey)
        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        let headerHMACSHA256FromFile = try reader.readDataPublic(length: 32)
        if !ConstantTime.equals(headerHMACSHA256, headerHMACSHA256FromFile) {
            throw KDBXReader.Error.wrongCredentials
        }

        let payload = try decryptBlockStreamAndDecompress(
            data: data,
            pos: reader.cursor.position,
            header: header,
            unlockKey: unlockKey,
            maxDecompressedPayloadSize: maxDecompressedPayloadSize
        )

        return DecryptedKDBXPayload(header: header, unlockKey: unlockKey, payload: payload)
    }

    /// Variant of `decryptAndDecompress` that reuses an already-derived
    /// `unlockKey` and an already-parsed `header` — saves the
    /// (expensive) KDF run on the re-stream path.
    static func decryptAndDecompressUsing(
        _ data: Data,
        unlockKey: SecureBytes,
        header: Header,
        maxDecompressedPayloadSize: Int
    ) throws -> DecryptedKDBXPayload {
        var reader = KDBXReader(data)
        // Skip past the header that the caller already parsed.
        // The cleartext header layout is deterministic given Header
        // (its byte length is what HeaderReader returned at open
        // time). For now we re-parse it cheaply — only the header is
        // touched, not the encrypted body.
        let headerLength: Int
        do {
            var headerReader = HeaderReader(data: data)
            (_, headerLength) = try headerReader.parse()
        } catch {
            throw KDBXReader.Error.corruptedHeader(reason: "Header re-parse failed during re-stream")
        }
        reader.cursor.advance(by: headerLength)
        // Skip SHA + HMAC of header (32 + 32 bytes) — already validated
        // at open time. We don't need to re-validate on re-stream;
        // the encrypted block stream HMAC validates each block we
        // touch.
        _ = try reader.readDataPublic(length: 32)
        _ = try reader.readDataPublic(length: 32)

        let payload = try decryptBlockStreamAndDecompress(
            data: data,
            pos: reader.cursor.position,
            header: header,
            unlockKey: unlockKey,
            maxDecompressedPayloadSize: maxDecompressedPayloadSize
        )
        return DecryptedKDBXPayload(header: header, unlockKey: unlockKey, payload: payload)
    }

    private static func decryptBlockStreamAndDecompress(
        data: Data,
        pos: Data.Index,
        header: Header,
        unlockKey: SecureBytes,
        maxDecompressedPayloadSize: Int
    ) throws -> Data {
        var reader = KDBXReader(data)
        reader.cursor.seek(to: pos)

        var blockIndex: UInt64 = 0
        var payload = Data(capacity: data.count)
        while true {
            let hmacFromFile = try reader.readDataPublic(length: 32)
            let size = try reader.readInt32Public()
            let block = try reader.readDataPublic(length: Int(size))

            // Authenticate every block, including the size-0 sentinel.
            // Skipping the sentinel HMAC opens a truncation attack — see
            // the matching comment in KDBXReader.swift's eager path.
            let blockKey = HMACProtectedBlockStream.keyForBlock(
                at: blockIndex,
                masterSalt: header.masterSalt,
                unlockKey: unlockKey
            )
            var digest = HMAC<SHA256>(key: SymmetricKey(data: blockKey))
            digest.update(data: blockIndex.dataLE)
            digest.update(data: size.dataLE)
            digest.update(data: block)
            let hmac = Data(digest.finalize())
            if !ConstantTime.equals(hmac, hmacFromFile) {
                throw KDBXReader.Error.corruptedHMAC(reason: "Block \(blockIndex) HMAC mismatch")
            }

            if size == 0 {
                break
            }
            payload.append(block)
            blockIndex += 1
        }

        // Decrypt
        let mainContentKey: SecureBytes = MainKey.make(masterSalt: header.masterSalt, unlockKey: unlockKey)
        switch header.encryptionAlgorithm {
        case .AES256CBC:
            let keyData = mainContentKey.withUnsafeBytes { keyPtr in
                Data(keyPtr.bindMemory(to: UInt8.self))
            }
            do {
                payload = try AES256CBC.decrypt(iv: header.encryptionNonce, cipherText: payload, keyData)
            } catch {
                throw KDBXReader.Error.corruptedHMAC(reason: "AES-256-CBC decrypt failed after HMAC verification: \(error)")
            }
        case .ChaCha20:
            let chaCha20: ChaCha20
            do {
                chaCha20 = try mainContentKey.withUnsafeBytes { keyPtr in
                    try ChaCha20(key: Data(keyPtr.bindMemory(to: UInt8.self)), iv: header.encryptionNonce)
                }
            } catch {
                throw KDBXReader.Error.corruptedHeader(reason: "Failed to initialize ChaCha20: invalid key or nonce")
            }
            payload = Data(chaCha20.decrypt(payload))
        }

        // Decompress
        switch header.compressionAlgorithm {
        case .none:
            break
        case .gzip:
            do {
                payload = try GzipStreamReader.decompress(payload, maxOutputBytes: maxDecompressedPayloadSize)
            } catch ZlibError.outputTooLarge {
                throw KDBXReader.Error.decompressedPayloadTooLarge(limit: maxDecompressedPayloadSize)
            } catch {
                throw KDBXReader.Error.corruptedXML(reason: "Failed to decompress: \(error)")
            }
        }
        return payload
    }
}

// MARK: - Internal read helpers exposed for lazy path

extension KDBXReader {
    /// `readData(length:)` is private to the eager parse; the lazy and
    /// streaming pipelines need the same bytes-from-stream behavior. These
    /// thin wrappers forward to the shared `cursor` so all paths share one
    /// bounds-checked implementation.
    mutating func readDataPublic(length: Int) throws(KDBXReader.Error) -> Data {
        do { return try cursor.readData(length: length) } catch { throw .unexpectedEOF }
    }

    mutating func readInt32Public() throws(KDBXReader.Error) -> Int32 {
        do { return try cursor.readInt32LE() } catch { throw .unexpectedEOF }
    }
}
