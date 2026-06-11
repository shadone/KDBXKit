//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

public extension KDBXWriter {
    /// Streaming write. Encrypts + compresses + HMAC-blocks the
    /// cleartext payload through a chain of stream consumers so peak
    /// in-process memory during save is bounded by one attachment at
    /// a time (via `BinarySource`) plus the pipeline's working
    /// buffers (~64 KB gzip + ~16 B AES + ~1 MB HMAC block) —
    /// independent of total attachment bytes.
    ///
    /// The write is atomic with respect to `outputURL`: bytes are staged
    /// into a sibling temp file and swapped into place only after the
    /// whole pipeline finalizes, so a mid-save failure (disk-full, a
    /// throwing `BinarySource`, process kill) leaves any existing file
    /// at `outputURL` untouched.
    ///
    /// - Parameters:
    ///   - outputURL: where to write the .kdbx file.
    ///   - content: the vault structure. Its `innerHeader.binaryContent`
    ///     contributes shape (count, ordering) but **not** bytes — the
    ///     bytes for each pool entry come from `binaries[i]`.
    ///   - binaries: per-pool-index byte sources, in pool order.
    ///   - unlockData: master credentials.
    ///   - regenerateSalts: per spec; default true. Set false for
    ///     deterministic round-trip tests.
    static func streamingWrite(
        to outputURL: URL,
        content: KDBXContent,
        binaries: [any BinarySource],
        unlockData: UnlockData,
        regenerateSalts: Bool = true
    ) throws {
        var prepared = regenerateSalts ? KDBXWriter.regeneratingSalts(in: content) : content
        // The streaming writer is the production save path for the
        // Passie iOS / macOS apps. It must clamp the format version
        // to 4.1 for the same reason the eager `write(_:unlockData:…)`
        // path does: this writer only emits KDBX 4 framing (UInt32
        // header field lengths, HMAC-protected block stream, inner-
        // header binary pool). A KDBXContent carrying formatVersion
        // 3.1 reaches here when a user imports a KeePassXC-default
        // vault; without the clamp the resulting file would carry
        // 4.x bytes under a 3.x version header — unparseable, with
        // post-write verification reporting a malformed cipher UUID
        // because the reader is parsing UInt16-length fields.
        prepared = KDBXWriter.clampingFormatVersionToWritable(prepared)

        // Save-time integrity. The unknown-KDF check must precede header
        // serialization — toVariantDictionary() has a fatalError for it.
        if case let .unknown(uuid) = prepared.header.kdfParameters {
            throw Error.unsupportedKDF(uuid)
        }

        // The emitted pool is exactly `binaries`, so
        // its count must match the inner-header shape, and every Ref in
        // the XML must resolve into it. A mismatch would serialize a
        // structurally valid vault with silently missing or mis-bound
        // attachments — the incident class that already shipped once.
        guard binaries.count == prepared.innerHeader.binaryContent.count else {
            throw Error.binarySourceCountMismatch(
                sources: binaries.count,
                poolEntries: prepared.innerHeader.binaryContent.count
            )
        }
        if let dangling = prepared.database.firstDanglingBinaryRef(poolCount: binaries.count) {
            throw Error.danglingBinaryRef(entryUUID: dangling.entryUUID, ref: dangling.ref, poolCount: binaries.count)
        }

        let headerData = try serializeHeaderBlock(prepared.header)
        let unlockKey = try deriveUnlockKey(prepared: prepared, unlockData: unlockData)
        let mainContentKey: SecureBytes = MainKey.make(
            masterSalt: prepared.header.masterSalt,
            unlockKey: unlockKey
        )

        // Stage into a sibling temp file (same directory, so the final
        // swap never crosses a volume) and replace the destination only
        // after the pipeline finalizes. Truncating outputURL directly
        // would turn any mid-save failure into loss of the existing vault.
        let tempURL = outputURL.deletingLastPathComponent()
            .appendingPathComponent(".\(outputURL.lastPathComponent).tmp-\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: tempURL.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: tempURL.path])
        }
        var swappedIntoPlace = false
        defer {
            if !swappedIntoPlace {
                try? FileManager.default.removeItem(at: tempURL)
            }
        }

        let fileHandle = try FileHandle(forWritingTo: tempURL)
        defer { try? fileHandle.close() }
        try writeHeaderPrologue(fileHandle: fileHandle, headerData: headerData, unlockKey: unlockKey, header: prepared.header)

        let pipeline = try buildPipeline(
            fileHandle: fileHandle,
            header: prepared.header,
            unlockKey: unlockKey,
            mainContentKey: mainContentKey
        )

        try emitInnerHeader(into: pipeline, innerHeader: prepared.innerHeader, binaries: binaries)
        try emitXML(into: pipeline, database: prepared.database, innerHeader: prepared.innerHeader)
        try pipeline.finalize()
        try fileHandle.close()

        if FileManager.default.fileExists(atPath: outputURL.path) {
            _ = try FileManager.default.replaceItemAt(outputURL, withItemAt: tempURL)
        } else {
            try FileManager.default.moveItem(at: tempURL, to: outputURL)
        }
        swappedIntoPlace = true
    }

    private static func serializeHeaderBlock(_ header: Header) throws -> Data {
        let headerStream = OutputStream(toMemory: ())
        headerStream.open()
        do {
            try HeaderWriter(to: headerStream).write(header)
        } catch {
            // `error` is `HeaderWriter.Error` via typed throws — no cast.
            switch error {
            case .unexpectedEOF: throw KDBXWriter.Error.unexpectedEOF
            case let .unknown(reason): throw KDBXWriter.Error.headerSerializationFailed(reason: reason)
            }
        }
        guard let data = headerStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw KDBXWriter.Error.headerSerializationFailed(reason: "Memory output stream did not return Data")
        }
        return data
    }

    private static func deriveUnlockKey(prepared: KDBXContent, unlockData: UnlockData) throws -> SecureBytes {
        do {
            return try unlockData.computeUnlockKey(kdfParameters: prepared.header.kdfParameters)
        } catch {
            // `error` is `UnlockDataError` via typed throws.
            switch error {
            case let .unsupportedKDF(uuid):
                throw KDBXWriter.Error.unsupportedKDF(uuid)
            case let .kdfFailed(reason):
                throw KDBXWriter.Error.encryptionFailed(reason: "KDF rejected parameters: \(reason)")
            case let .unsupportedKDFParameter(name):
                throw KDBXWriter.Error.encryptionFailed(reason: "Unsupported KDF parameter: \(name)")
            case let .kdfParametersOutOfRange(reason):
                throw KDBXWriter.Error.encryptionFailed(reason: "KDF parameters exceed policy: \(reason)")
            }
        }
    }

    private static func writeHeaderPrologue(
        fileHandle: FileHandle,
        headerData: Data,
        unlockKey: SecureBytes,
        header: Header
    ) throws {
        try fileHandle.write(contentsOf: headerData)
        try fileHandle.write(contentsOf: headerData.sha256())
        let headerKey = HMACProtectedBlockStream.keyForHeader(
            masterSalt: header.masterSalt,
            unlockKey: unlockKey
        )
        try fileHandle.write(contentsOf: headerData.hmacSha256(key: headerKey))
    }

    private static func buildPipeline(
        fileHandle: FileHandle,
        header: Header,
        unlockKey: SecureBytes,
        mainContentKey: SecureBytes
    ) throws -> any StreamingByteConsumer {
        let hmacBlock = HMACBlockStreamWriter(
            fileHandle: fileHandle,
            masterSalt: header.masterSalt,
            unlockKey: unlockKey
        )
        let encrypt = try EncryptingStreamWriter(
            header: header,
            mainKey: mainContentKey,
            downstream: hmacBlock
        )
        switch header.compressionAlgorithm {
        case .none:
            return encrypt
        case .gzip:
            return try GzipStreamWriter(downstream: encrypt)
        }
    }

    private static func emitInnerHeader(
        into pipeline: any StreamingByteConsumer,
        innerHeader: InnerHeader,
        binaries: [any BinarySource]
    ) throws {
        try emitTLV(
            type: .encryptionAlgorithm,
            value: innerHeader.encryptionAlgorithm.rawValue.toDataLittleEndian(),
            into: pipeline
        )
        let encryptionKeyData = innerHeader.encryptionKey.withUnsafeBytes { keyPtr in
            Data(keyPtr.bindMemory(to: UInt8.self))
        }
        try emitTLV(type: .encryptionKey, value: encryptionKeyData, into: pipeline)
        for source in binaries {
            try emitBinaryTLV(source, into: pipeline)
        }
        try emitTLV(type: .endOfHeader, value: Data(), into: pipeline)
    }

    private static func emitXML(
        into pipeline: any StreamingByteConsumer,
        database: KDBX,
        innerHeader: InnerHeader
    ) throws {
        let xmlStream = OutputStream(toMemory: ())
        xmlStream.open()
        let innerEncryptor: any Encryptable
        do {
            innerEncryptor = try innerHeader.makeEncryptor()
        } catch {
            throw KDBXWriter.Error.encryptionFailed(reason: "Inner-stream key derivation failed: \(error)")
        }
        do {
            try XMLDocumentWriter(to: xmlStream, encryptor: innerEncryptor).write(database)
        } catch {
            // `error` is `XMLDocumentWriter.Error` via typed throws.
            switch error {
            case .unexpectedEOF: throw KDBXWriter.Error.unexpectedEOF
            case let .unknown(reason): throw KDBXWriter.Error.xmlSerializationFailed(reason: reason)
            }
        }
        guard let data = xmlStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw KDBXWriter.Error.xmlSerializationFailed(reason: "Memory output stream did not return Data")
        }
        try pipeline.consume(data)
    }

    private static func emitTLV(
        type: InnerHeaderFieldType,
        value: Data,
        into pipeline: any StreamingByteConsumer
    ) throws {
        var prefix = Data()
        prefix.append(type.rawValue)
        prefix.append(Int32(value.count).toDataLittleEndian())
        try pipeline.consume(prefix)
        if !value.isEmpty {
            try pipeline.consume(value)
        }
    }

    private static func emitBinaryTLV(
        _ source: any BinarySource,
        into pipeline: any StreamingByteConsumer
    ) throws {
        let length = Int32(source.sizeBytes + 1)
        var prefix = Data()
        prefix.append(InnerHeaderFieldType.binaryContent.rawValue)
        prefix.append(length.toDataLittleEndian())
        prefix.append(source.shouldBeProtected ? 0x01 : 0x00)
        try pipeline.consume(prefix)

        var sink = PipelineByteSink(pipeline: pipeline)
        try source.stream(into: &sink)
    }
}

/// ByteSink adapter forwarding writes into a pipeline. `finalize`
/// is intentionally a no-op — the pipeline is finalized once at the
/// end of streamingWrite, not after each binary.
private struct PipelineByteSink: ByteSink {
    let pipeline: any StreamingByteConsumer
    mutating func write(_ chunk: UnsafeRawBufferPointer) throws {
        guard let base = chunk.baseAddress, !chunk.isEmpty else { return }
        try pipeline.consume(Data(bytes: base, count: chunk.count))
    }

    mutating func finalize() throws { }
}
