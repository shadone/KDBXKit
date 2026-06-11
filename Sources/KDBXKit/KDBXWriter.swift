//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// Writes a `KDBXContent` to a `.kdbx` byte stream.
///
/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.                           <<- writes
/// 2. SHA-256 hash of the header.       <<- writes
/// 3. HMAC-SHA-256 hash of the header.  <<- writes
/// 4. In HMAC-protected block stream:   <<- writes
///    a. Encrypted:                     <<- encrypts
///       i. Compressed (optional):      <<- compresses
///          - Inner header.             <<- writes
///          - XML document.             <<- writes
/// ```
///
/// https://keepass.info/help/kb/kdbx.html
public struct KDBXWriter {
    /// Errors raised by `KDBXWriter.write`.
    public enum Error: Swift.Error, Sendable {
        // MARK: - I/O

        /// The underlying output stream returned an error during a write.
        case streamWriteFailed(any Swift.Error)

        /// The output stream was not in the `.open` state when `write()` was
        /// called. Caller must open the stream first.
        case streamNotOpen

        /// Buffer exhausted — only meaningful when writing to a fixed-size
        /// memory stream that can't grow.
        case unexpectedEOF

        // MARK: - Serialization

        /// Producing the cleartext header bytes failed.
        case headerSerializationFailed(reason: String)

        /// Producing the cleartext inner-header bytes failed.
        case innerHeaderSerializationFailed(reason: String)

        /// Producing the cleartext XML document failed.
        case xmlSerializationFailed(reason: String)

        // MARK: - Format/feature support

        /// The KDF UUID in the content header isn't supported by KDBXKit.
        case unsupportedKDF(UUID)

        // MARK: - Crypto

        /// Encryption of the main payload failed.
        case encryptionFailed(reason: String)

        /// Compression of the main payload failed.
        case compressionFailed(reason: String)

        // MARK: - Save-time integrity

        /// An entry (live or history) references a binary-pool index
        /// that doesn't exist in the pool being written. Serializing it
        /// would produce a structurally valid vault whose attachment is
        /// silently gone — the save is refused instead.
        case danglingBinaryRef(entryUUID: UUID, ref: UInt32, poolCount: Int)

        /// `streamingWrite` was handed a `binaries` array whose count
        /// doesn't match `innerHeader.binaryContent` — the emitted pool
        /// would not line up with the refs serialized into the XML.
        case binarySourceCountMismatch(sources: Int, poolEntries: Int)
    }

    let outputStream: OutputStream

    public init(to outputStream: OutputStream) {
        self.outputStream = outputStream
    }

    private func write(_ data: Data) throws(Error) {
        do {
            try outputStream.write(data: data)
        } catch {
            switch error {
            case let .streamError(streamError):
                if let streamError {
                    throw .streamWriteFailed(streamError)
                } else {
                    throw .streamWriteFailed(NSError(
                        domain: "KDBXWriter", code: 1,
                        userInfo: [NSLocalizedDescriptionKey: "Unknown stream error"]
                    ))
                }
            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }
    }

    private func serialize(_ header: Header) throws(Error) -> Data {
        let headerOutputStream = OutputStream(toMemory: ())
        headerOutputStream.open()

        do {
            try HeaderWriter(to: headerOutputStream).write(header)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .headerSerializationFailed(reason: reason)
            }
        }

        guard let data = headerOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw .headerSerializationFailed(reason: "Memory output stream did not return Data")
        }

        return data
    }

    private func serialize(_ innerHeader: InnerHeader) throws(Error) -> Data {
        let innerHeaderOutputStream = OutputStream(toMemory: ())
        innerHeaderOutputStream.open()

        do {
            try InnerHeaderWriter(to: innerHeaderOutputStream).write(innerHeader)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .innerHeaderSerializationFailed(reason: reason)
            }
        }

        guard let data = innerHeaderOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw .innerHeaderSerializationFailed(reason: "Memory output stream did not return Data")
        }

        return data
    }

    private func serialize(_ database: KDBX, encryptor: any Encryptable) throws(Error) -> Data {
        let xmlDocumentOutputStream = OutputStream(toMemory: ())
        xmlDocumentOutputStream.open()

        do {
            try XMLDocumentWriter(to: xmlDocumentOutputStream, encryptor: encryptor).write(database)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .xmlSerializationFailed(reason: reason)
            }
        }

        guard let data = xmlDocumentOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            throw .xmlSerializationFailed(reason: "Memory output stream did not return Data")
        }

        return data
    }

    private func writeHMACProtectedBlock(
        index blockIndex: UInt64,
        data: Data,
        masterSalt: Data,
        unlockKey: SecureBytes
    ) throws(Error) {
        let blockKey = HMACProtectedBlockStream.keyForBlock(
            at: UInt64(blockIndex),
            masterSalt: masterSalt,
            unlockKey: unlockKey
        )

        let blockSize = Int32(data.count)

        var digest = HMAC<SHA256>(key: SymmetricKey(data: blockKey))
        digest.update(data: UInt64(blockIndex).dataLE)
        digest.update(data: blockSize.dataLE)
        digest.update(data: data)
        let hmac = Data(digest.finalize())

        try write(hmac)
        try write(blockSize.dataLE)
        try write(data)
    }

    /// Serialize a vault to the output stream.
    ///
    /// - Parameters:
    ///   - content: the vault to write.
    ///   - unlockData: the user's key (password and/or key file).
    ///   - regenerateSalts: when `true` (the default — and what the spec
    ///     mandates), `masterSalt`, `encryptionNonce`, and the KDF salt are
    ///     replaced with fresh CSPRNG bytes before encryption. The on-disk
    ///     file differs every time you save the same content with the same
    ///     password. Set to `false` only when you need deterministic output
    ///     (round-trip tests, integration fixtures).
    public func write(
        _ content: KDBXContent,
        unlockData: UnlockData,
        regenerateSalts: Bool = true
    ) throws(Error) {
        guard outputStream.streamStatus == .open else {
            throw .streamNotOpen
        }

        // Per the KDBX spec: masterSalt, encryptionNonce, the KDF salt, and
        // the inner random-stream key MUST be regenerated on every save.
        // Reusing them with the same key gives an attacker access to the
        // same ciphertext for the same plaintext, weakening confidentiality.
        // Default-on; the round-trip tests can opt out for exact
        // byte-equality.
        var preparedContent = regenerateSalts ? Self.regeneratingSalts(in: content) : content

        // ``KDBXWriter`` only emits the KDBX 4 on-disk shape — UInt32
        // header field lengths, kdfParameters VariantDictionary,
        // HMAC-protected block stream, inner-header binary pool. A
        // ``KDBXContent`` carrying ``formatVersion`` 3.0 / 3.1 reaches
        // here in two ways: it was just read from a legacy file, or a
        // caller constructed one programmatically. In either case the
        // safe answer is the same — clamp the version field so the
        // bytes we produce are unambiguously identified as 4.1. Doing
        // anything else would write the new 4.x framing under a 3.x
        // version number and silently corrupt the file.
        preparedContent = Self.clampingFormatVersionToWritable(preparedContent)

        // MARK: 0. Save-time integrity

        // Must precede header serialization: toVariantDictionary() has a
        // fatalError for .unknown, and parseHeader (credential-free) hands
        // callers headers carrying unknown KDF UUIDs.
        if case let .unknown(uuid) = preparedContent.header.kdfParameters {
            throw .unsupportedKDF(uuid)
        }

        let poolCount = preparedContent.innerHeader.binaryContent.count
        if let dangling = preparedContent.database.firstDanglingBinaryRef(poolCount: poolCount) {
            throw .danglingBinaryRef(entryUUID: dangling.entryUUID, ref: dangling.ref, poolCount: poolCount)
        }

        // MARK: 1. Header

        let headerData = try serialize(preparedContent.header)
        try write(headerData)

        // MARK: 2. SHA-256 of the header

        let headerSHA256 = headerData.sha256()
        try write(headerSHA256)

        // MARK: 3. HMAC-SHA256 of the header

        let unlockKey: SecureBytes
        do throws(UnlockDataError) {
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: preparedContent.header.kdfParameters)
        } catch {
            switch error {
            case let .unsupportedKDF(uuid):
                throw .unsupportedKDF(uuid)
            case let .kdfFailed(reason):
                throw .encryptionFailed(reason: "KDF rejected parameters: \(reason)")
            case let .unsupportedKDFParameter(name):
                throw .encryptionFailed(reason: "Unsupported KDF parameter: \(name)")
            case let .kdfParametersOutOfRange(reason):
                throw .encryptionFailed(reason: "KDF parameters exceed policy: \(reason)")
            }
        }

        let headerKey = HMACProtectedBlockStream.keyForHeader(
            masterSalt: preparedContent.header.masterSalt,
            unlockKey: unlockKey
        )

        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        try write(headerHMACSHA256)

        // MARK: 4. Prepare for HMAC-protected block stream

        var payload = Data()

        // MARK: 4.a Serialize Inner Header

        payload += try serialize(preparedContent.innerHeader)

        // MARK: 4.b Serialize XML Document

        let innerEncryptor: any Encryptable
        do {
            innerEncryptor = try preparedContent.innerHeader.makeEncryptor()
        } catch {
            throw .encryptionFailed(reason: "Inner-stream key derivation failed: \(error)")
        }
        payload += try serialize(preparedContent.database, encryptor: innerEncryptor)

        // MARK: 4.c Compress payload if needed

        switch preparedContent.header.compressionAlgorithm {
        case .none:
            break

        case .gzip:
            do {
                payload = try GzipOneShot.compress(payload)
            } catch {
                throw .compressionFailed(reason: "\(error)")
            }
        }

        // MARK: 4.d Encrypt payload

        let mainContentKey: SecureBytes = MainKey.make(masterSalt: preparedContent.header.masterSalt, unlockKey: unlockKey)

        switch preparedContent.header.encryptionAlgorithm {
        case .AES256CBC:
            let keyData = mainContentKey.withUnsafeBytes { keyPtr in
                Data(keyPtr.bindMemory(to: UInt8.self))
            }
            do {
                payload = try AES256CBC.encrypt(
                    iv: preparedContent.header.encryptionNonce,
                    plainText: payload,
                    keyData
                )
            } catch {
                throw .encryptionFailed(reason: "AES-256-CBC: \(error)")
            }

        case .ChaCha20:
            let chaCha20: ChaCha20
            do {
                chaCha20 = try mainContentKey.withUnsafeBytes { keyPtr in
                    try ChaCha20(
                        key: Data(keyPtr.bindMemory(to: UInt8.self)),
                        iv: preparedContent.header.encryptionNonce
                    )
                }
            } catch {
                throw .encryptionFailed(reason: "Failed to initialize ChaCha20: invalid key or nonce")
            }
            // ChaCha20 is a stream cipher; encrypt and decrypt are the same XOR
            // operation, but call out the direction here for readability — this
            // is the encryption path.
            payload = Data(chaCha20.encrypt(payload))
        }

        // MARK: 4.e Write HMAC-protected block stream

        // A very small block size results in a large KDBX file (due to the additional HMACs and
        // size values).
        // A very large block size requires a lot of process memory.
        //
        // So, except in special cases (e.g. a small block at the end of the file), neither the
        // minimum nor the maximum is a good choice for the block size; a good size is in the
        // "middle".
        //
        // When saving a KDBX file, KeePass currently uses 1048576 (i.e. 1 MB) as size for every
        // input block except the last one (which may be smaller).
        let blockSize = 1_048_576

        var blockIndex: UInt64 = 0
        for start in stride(from: 0, to: payload.count, by: blockSize) {
            let end = min(start + blockSize, payload.endIndex)
            let block = payload.subdata(in: start..<end)

            try writeHMACProtectedBlock(
                index: blockIndex,
                data: block,
                masterSalt: preparedContent.header.masterSalt,
                unlockKey: unlockKey
            )

            blockIndex += 1
        }

        // The HMAC-protected block stream is terminated by an output block for an empty input block
        // (i.e. M empty, s = 0).
        try writeHMACProtectedBlock(
            index: blockIndex,
            data: Data(),
            masterSalt: preparedContent.header.masterSalt,
            unlockKey: unlockKey
        )
    }

    /// Returns a copy of `content` with fresh CSPRNG bytes for the master
    /// salt, encryption nonce, KDF salt, and inner random-stream key. Per
    /// KDBX spec these must be regenerated on every save — leaving them
    /// stale across saves weakens confidentiality (same key + same
    /// plaintext → same ciphertext).
    /// Upgrade `content.header.formatVersion` to the on-disk format the
    /// writer actually emits when the input is from a pre-4 format.
    ///
    /// The writer's serializer is unconditionally 4.x — there is no
    /// branch that emits 3.x bytes. A 3.x version number on 4.x bytes
    /// would yield a file that no compliant reader (including ours)
    /// could parse, so the clamp is mandatory rather than an opt-in.
    static func clampingFormatVersionToWritable(_ content: KDBXContent) -> KDBXContent {
        guard content.header.formatVersion.isLegacy3x else {
            return content
        }
        let upgraded = Header(
            formatVersion: .v4_1,
            encryptionAlgorithm: content.header.encryptionAlgorithm,
            compressionAlgorithm: content.header.compressionAlgorithm,
            masterSalt: content.header.masterSalt,
            encryptionNonce: content.header.encryptionNonce,
            kdfParameters: content.header.kdfParameters,
            publicCustomData: content.header.publicCustomData
        )
        return KDBXContent(
            database: content.database,
            header: upgraded,
            innerHeader: content.innerHeader,
            parserWarnings: content.parserWarnings,
            // The on-disk file we're about to emit is 4.x, so the
            // notice no longer applies. Callers reading the file back
            // will see legacyFormatNotice == nil.
            legacyFormatNotice: nil
        )
    }

    static func regeneratingSalts(in content: KDBXContent) -> KDBXContent {
        let header = content.header

        // Nonce length depends on the cipher.
        let nonceLength: Int
        switch header.encryptionAlgorithm {
        case .AES256CBC: nonceLength = 16
        case .ChaCha20: nonceLength = 12
        }

        // KDF salt length: keep what was there (size is meaningful for some
        // KDFs and the writer shouldn't silently re-shape it), but refill
        // the bytes with random.
        let newKDF: KDFParameters
        switch header.kdfParameters {
        case let .aes(params, additional):
            newKDF = .aes(
                .init(salt: SecureRandom.bytes(params.salt.count), rounds: params.rounds),
                additional: additional
            )
        case let .argon2d(params, additional):
            newKDF = .argon2d(
                Header.Argon2WithFreshSalt(params),
                additional: additional
            )
        case let .argon2id(params, additional):
            newKDF = .argon2id(
                Header.Argon2WithFreshSalt(params),
                additional: additional
            )
        case .unknown:
            // Caller will fail at the KDF derivation step anyway; pass the
            // unknown KDF through unchanged so the error surfaces there.
            newKDF = header.kdfParameters
        }

        let newHeader = Header(
            formatVersion: header.formatVersion,
            encryptionAlgorithm: header.encryptionAlgorithm,
            compressionAlgorithm: header.compressionAlgorithm,
            masterSalt: SecureRandom.bytes(32),
            encryptionNonce: SecureRandom.bytes(nonceLength),
            kdfParameters: newKDF,
            publicCustomData: header.publicCustomData
        )

        // The inner random-stream key is regenerated per save as well
        // (KeePass and KeePassXC do the same). Safe for lazyInnerCipher
        // values: they decrypt with the reader's retained keystream
        // source and re-encrypt with the writer's fresh encryptor. The
        // key length is fixed per algorithm.
        var newInnerHeader = content.innerHeader
        let innerKeyLength: Int
        switch newInnerHeader.encryptionAlgorithm {
        case .ChaCha20: innerKeyLength = 64
        case .Salsa20: innerKeyLength = 32
        }
        newInnerHeader.encryptionKey = SecureBytes(SecureRandom.bytes(innerKeyLength))

        return KDBXContent(
            database: content.database,
            header: newHeader,
            innerHeader: newInnerHeader
        )
    }
}

private extension Header {
    /// Replaces only the salt of an `Argon2` parameter block, preserving
    /// iteration / memory / parallelism / version.
    static func Argon2WithFreshSalt(_ p: KDFParameters.Argon2) -> KDFParameters.Argon2 {
        KDFParameters.Argon2(
            version: p.version,
            salt: SecureRandom.bytes(p.salt.count),
            iterations: p.iterations,
            memory: p.memory,
            parallelism: p.parallelism
        )
    }
}
