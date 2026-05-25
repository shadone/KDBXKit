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
        maxDecompressedPayloadSize: Int = KDBXReader.maxDecompressedPayloadSize
    ) throws -> LazyKDBXContent {
        let encrypted = try source.readAll()
        let decrypted = try decryptAndDecompress(
            encrypted,
            unlockData: unlockData,
            maxDecompressedPayloadSize: maxDecompressedPayloadSize
        )

        // Parse inner header in metadata mode — captures offsets +
        // hashes for every binary, returns InnerHeader with empty
        // binaryContent.
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
    /// source, replays decrypt + decompress, locates the target
    /// binary at its decompressed offset, and writes `length` bytes
    /// to the sink. Peak memory during the call: ~file_size briefly;
    /// after return: nothing retained.
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
        let meta = lazy.binaries[index]

        let encrypted = try lazy.source.readAll()
        let decrypted = try decryptAndDecompressUsing(
            encrypted,
            unlockKey: lazy.unlockKey,
            header: lazy.header,
            maxDecompressedPayloadSize: lazy.maxDecompressedPayloadSize
        )

        // Slice the binary out of the decompressed payload and feed
        // sink in chunks. The Data subdata is a view onto the parent
        // buffer; no extra copy. Chunk writes let the sink stream
        // (URLSink to disk, SecureBytesSink page-by-page) instead of
        // materializing the full bytes into the sink's storage at
        // once for very large attachments.
        let start = decrypted.payload.startIndex + meta.decompressedOffset
        let end = start + meta.decompressedLength
        guard end <= decrypted.payload.endIndex else {
            throw KDBXReader.Error.corruptedInnerHeader(
                reason: "Binary slice [\(meta.decompressedOffset)..<\(end)] exceeds payload bounds"
            )
        }
        let slice = decrypted.payload[start..<end]

        let chunkSize = 64 * 1024
        var cursor = slice.startIndex
        while cursor < slice.endIndex {
            let next = min(slice.index(cursor, offsetBy: chunkSize, limitedBy: slice.endIndex) ?? slice.endIndex, slice.endIndex)
            try slice[cursor..<next].withUnsafeBytes { buf in
                try sink.write(buf)
            }
            cursor = next
        }
        try sink.finalize()
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
        maxDecompressedPayloadSize: Int
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
        reader.pos = reader.pos.advanced(by: headerLength)

        // 2. SHA-256 of header
        let headerData = Data(data[..<headerLength])
        let headerSHA256 = headerData.sha256()
        let headerSHA256FromFile = try reader.readDataPublic(length: 32)
        if !ConstantTime.equals(headerSHA256, headerSHA256FromFile) {
            throw KDBXReader.Error.corruptedHeaderDigest
        }

        // 3. HMAC-SHA256 of header
        let unlockKey: SecureBytes
        do throws(UnlockDataError) {
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: header.kdfParameters)
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
        let headerKey = HMACProtectedBlockStream.keyForHeader(masterSalt: header.masterSalt, unlockKey: unlockKey)
        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        let headerHMACSHA256FromFile = try reader.readDataPublic(length: 32)
        if !ConstantTime.equals(headerHMACSHA256, headerHMACSHA256FromFile) {
            throw KDBXReader.Error.wrongCredentials
        }

        let payload = try decryptBlockStreamAndDecompress(
            data: data,
            pos: reader.pos,
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
        reader.pos = reader.pos.advanced(by: headerLength)
        // Skip SHA + HMAC of header (32 + 32 bytes) — already validated
        // at open time. We don't need to re-validate on re-stream;
        // the encrypted block stream HMAC validates each block we
        // touch.
        _ = try reader.readDataPublic(length: 32)
        _ = try reader.readDataPublic(length: 32)

        let payload = try decryptBlockStreamAndDecompress(
            data: data,
            pos: reader.pos,
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
        reader.pos = pos

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
    /// `readData(length:)` is private to the eager parse; the lazy
    /// pipeline needs the same bytes-from-stream behavior. Renamed
    /// public-ish so the helper functions above can call it without
    /// exposing parser internals.
    mutating func readDataPublic(length: Int) throws(KDBXReader.Error) -> Data {
        let start = pos
        let end = pos.advanced(by: length)
        if end > data.endIndex {
            throw .unexpectedEOF
        }
        let subdata = data.subdata(in: start..<end)
        pos = end
        return subdata
    }

    mutating func readInt32Public() throws(KDBXReader.Error) -> Int32 {
        try readDataPublic(length: 4).asInt32LE()!
    }
}
