//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

public extension KDBXReader {
    /// Fully streaming metadata-only open. Unlike ``openMetadataOnly``,
    /// which decrypts and decompresses the **whole** payload into one
    /// buffer before parsing (peak ≈ the full decompressed size — the
    /// attachments included), this reads the HMAC block stream one block
    /// at a time, decrypts and inflates incrementally, and **discards each
    /// binary-pool payload as it streams** — only the XML is retained.
    ///
    /// Peak memory is therefore ≈ the XML size plus a small window,
    /// independent of attachment bytes. This is the path memory-capped
    /// hosts (the iOS AutoFill credential-provider extension, jetsam-limited
    /// to ~220 MB) must use: the eager and `openMetadataOnly` paths both
    /// materialize the full binary pool and get killed mid-parse on vaults
    /// with large attachments.
    ///
    /// The returned ``LazyKDBXContent`` is byte-for-byte equivalent to what
    /// ``openMetadataOnly`` returns (same database, same per-binary
    /// metadata + offsets); attachment bytes are fetched on demand via
    /// ``streamBinary(from:at:into:)``.
    ///
    /// - note: 4.x only — KDBX 3.x stores binaries inline in the XML body,
    ///   so there is no separate binary pool to stream past. 3.x sources
    ///   throw `unsupportedFormatVersion`; callers fall back to eager
    ///   ``parse(_:unlockData:)`` (3.x files are migrated to 4.1 on save).
    static func openMetadataStreaming(
        from source: KDBXSource,
        unlockData: UnlockData,
        maxDecompressedPayloadSize: Int = KDBXReader.maxDecompressedPayloadSize,
        kdfLimits: KDFParameterLimits = .default
    ) throws -> LazyKDBXContent {
        // Map the file rather than copy it: mapped clean pages don't count
        // against phys_footprint, so the encrypted bytes stop scaling the
        // peak. Combined with block-by-block decrypt + binary discard, peak
        // is the KDF + XML working set — independent of vault size.
        let encrypted = try source.readAll(mappedIfSafe: true)
        let prep = try verifyHeaderAndDeriveKey(encrypted, unlockData: unlockData, kdfLimits: kdfLimits)
        let mainContentKey = MainKey.make(masterSalt: prep.header.masterSalt, unlockKey: prep.unlockKey)

        // Build the streaming chain: decrypt → (inflate) → discard-binaries
        // + keep-XML terminal consumer.
        let consumer = InnerHeaderXMLStreamConsumer()
        let decryptDownstream: any StreamingByteConsumer
        switch prep.header.compressionAlgorithm {
        case .none:
            decryptDownstream = consumer
        case .gzip:
            decryptDownstream = try StreamingInflateReader(
                downstream: consumer,
                maxOutputBytes: maxDecompressedPayloadSize
            )
        }
        let decryptor = try DecryptingStreamReader(
            header: prep.header,
            mainKey: mainContentKey,
            downstream: decryptDownstream
        )

        // Read + HMAC-verify each block, feed ciphertext into the chain.
        // ZlibError is internal — map decompression failures to the same
        // public typed errors the eager path surfaces.
        do {
            _ = try driveHMACBlocks(
                encrypted,
                from: prep.payloadPos,
                masterSalt: prep.header.masterSalt,
                unlockKey: prep.unlockKey,
                into: decryptor
            )
            try decryptor.finalize()
        } catch ZlibError.outputTooLarge {
            throw KDBXReader.Error.decompressedPayloadTooLarge(limit: maxDecompressedPayloadSize)
        } catch let error as ZlibError {
            throw KDBXReader.Error.corruptedXML(reason: "Failed to decompress: \(error)")
        }

        // Build the inner header + parse the accumulated XML — the same
        // tail as `openMetadataOnly`, just over the streamed buffers.
        let innerHeader = try consumer.makeInnerHeader()
        guard let xmlDocument = String(validating: consumer.xml, as: UTF8.self) else {
            throw KDBXReader.Error.corruptedXML(reason: "Failed to parse the XML document as a utf8 string")
        }

        let keystreamSource: KeystreamSource
        do {
            keystreamSource = try innerHeader.makeKeystreamSource()
        } catch {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Inner-stream key derivation failed: \(error)")
        }

        let database: KDBX
        var parserWarnings: [String] = []
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

        return LazyKDBXContent(
            database: database,
            header: prep.header,
            innerHeader: innerHeader,
            binaries: consumer.binaries,
            parserWarnings: parserWarnings,
            source: source,
            unlockKey: prep.unlockKey,
            maxDecompressedPayloadSize: maxDecompressedPayloadSize
        )
    }

    /// Parse the cleartext header, verify its SHA-256 + HMAC, and derive the
    /// unlock key — steps 1–3 of the KDBX read pipeline, stopping at the
    /// start of the encrypted block stream. Mirrors the prelude inside
    /// `decryptAndDecompress`; factored out so the streaming open shares the
    /// exact same verification before diverging into a per-block loop.
    internal static func verifyHeaderAndDeriveKey(
        _ data: Data,
        unlockData: UnlockData,
        kdfLimits: KDFParameterLimits
    ) throws -> (header: Header, unlockKey: SecureBytes, payloadPos: Data.Index) {
        var reader = KDBXReader(data)

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

        let headerData = Data(data[..<headerLength])
        let headerSHA256 = headerData.sha256()
        let headerSHA256FromFile = try reader.readDataPublic(length: 32)
        if !ConstantTime.equals(headerSHA256, headerSHA256FromFile) {
            throw KDBXReader.Error.corruptedHeaderDigest
        }

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
        let headerKey = HMACProtectedBlockStream.keyForHeader(masterSalt: header.masterSalt, unlockKey: unlockKey)
        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        let headerHMACSHA256FromFile = try reader.readDataPublic(length: 32)
        if !ConstantTime.equals(headerHMACSHA256, headerHMACSHA256FromFile) {
            throw KDBXReader.Error.wrongCredentials
        }

        return (header: header, unlockKey: unlockKey, payloadPos: reader.cursor.position)
    }

    /// Drive the KDBX 4 HMAC-protected outer block stream: read each block,
    /// authenticate it against its per-block key, and push the ciphertext
    /// into `consumer`. Shared by the streaming metadata open and the
    /// single-binary re-stream so both authenticate byte-for-byte the same.
    ///
    /// Returns `true` if it stopped early (because `stopEarly()` flipped
    /// after a block) and `false` if it ran to the size-0 sentinel. On an
    /// early stop the caller must NOT call `consumer.finalize()`: the
    /// inflate stage would report a truncated stream, and the caller
    /// already captured whatever it needed. The natural-completion path
    /// also leaves `finalize()` to the caller, so both call sites match.
    internal static func driveHMACBlocks(
        _ encrypted: Data,
        from payloadPos: Data.Index,
        masterSalt: Data,
        unlockKey: SecureBytes,
        into consumer: any StreamingByteConsumer,
        stopEarly: () -> Bool = { false }
    ) throws -> Bool {
        var reader = KDBXReader(encrypted)
        reader.cursor.seek(to: payloadPos)
        var blockIndex: UInt64 = 0
        while true {
            let hmacFromFile = try reader.readDataPublic(length: 32)
            let size = try reader.readInt32Public()
            let block = try reader.readDataPublic(length: Int(size))

            let blockKey = HMACProtectedBlockStream.keyForBlock(
                at: blockIndex,
                masterSalt: masterSalt,
                unlockKey: unlockKey
            )
            var digest = HMAC<SHA256>(key: SymmetricKey(data: blockKey))
            digest.update(data: blockIndex.dataLE)
            digest.update(data: size.dataLE)
            digest.update(data: block)
            if !ConstantTime.equals(Data(digest.finalize()), hmacFromFile) {
                throw KDBXReader.Error.corruptedHMAC(reason: "Block \(blockIndex) HMAC mismatch")
            }

            if size == 0 { return false }
            try consumer.consume(block)
            blockIndex += 1
            if stopEarly() { return true }
        }
    }

    /// Byte offset where the encrypted block stream begins, for the
    /// re-stream path that already holds a parsed ``Header`` + derived
    /// unlock key. Re-parses only the cleartext header (cheap, no KDF) and
    /// skips it plus the header SHA-256 + HMAC (32 + 32 bytes, already
    /// validated at open time — each block re-authenticates as it streams).
    internal static func payloadStart(in encrypted: Data) throws -> Data.Index {
        var reader = KDBXReader(encrypted)
        let headerLength: Int
        do {
            var headerReader = HeaderReader(data: encrypted)
            (_, headerLength) = try headerReader.parse()
        } catch {
            throw KDBXReader.Error.corruptedHeader(reason: "Header re-parse failed during re-stream")
        }
        reader.cursor.advance(by: headerLength)
        _ = try reader.readDataPublic(length: 32) // header SHA-256
        _ = try reader.readDataPublic(length: 32) // header HMAC
        return reader.cursor.position
    }
}
