//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoKit
import Foundation

public extension KDBXWriter {
    /// Streaming write. Encrypts + compresses + HMAC-blocks the
    /// cleartext payload through a chain of stream consumers so peak
    /// in-process memory during save is bounded by one attachment at
    /// a time (via `BinarySource`) plus the pipeline's working
    /// buffers (~64 KB gzip + ~16 B AES + ~1 MB HMAC block) —
    /// independent of total attachment bytes.
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
        let headerData = try serializeHeaderBlock(prepared.header)
        let unlockKey = try deriveUnlockKey(prepared: prepared, unlockData: unlockData)
        let mainContentKey: SecureBytes = MainKey.make(
            masterSalt: prepared.header.masterSalt,
            unlockKey: unlockKey
        )

        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let fileHandle = try FileHandle(forWritingTo: outputURL)
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
    }

    private static func serializeHeaderBlock(_ header: Header) throws -> Data {
        let headerStream = OutputStream(toMemory: ())
        headerStream.open()
        do {
            try HeaderWriter(to: headerStream).write(header)
        } catch let err as HeaderWriter.Error {
            switch err {
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
        } catch let kdfErr as UnlockDataError {
            switch kdfErr {
            case let .unsupportedKDF(uuid):
                throw KDBXWriter.Error.unsupportedKDF(uuid)
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
        do {
            try XMLDocumentWriter(to: xmlStream, encryptor: innerHeader.makeEncryptor()).write(database)
        } catch let err as XMLDocumentWriter.Error {
            switch err {
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
        guard let base = chunk.baseAddress, chunk.count > 0 else { return }
        try pipeline.consume(Data(bytes: base, count: chunk.count))
    }
    mutating func finalize() throws {}
}
