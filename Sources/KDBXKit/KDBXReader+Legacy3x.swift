//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// KDBX 3.x read pipeline. Kept in a separate extension so the 4.x
/// pipeline in ``KDBXReader.parse(unlockData:retainsXMLForDiagnostics:maxDecompressedPayloadSize:)``
/// stays readable — the two formats genuinely diverge at the framing
/// layer (UInt16 field lengths, no SHA/HMAC trailer, hashed block stream,
/// inline XML binaries) and interleaving them would force readers to load
/// both specs to follow either path.
///
/// What is *not* duplicated between the two pipelines: KDF derivation
/// (``UnlockData.computeUnlockKey``), main-key composition
/// (``MainKey.make``), AES-256-CBC primitives, the inner stream-cipher
/// keystream (``KeystreamSource``), and the XML reader itself — all of
/// these consume the unified ``Header`` / ``InnerHeader`` shapes that
/// ``Header3xReader`` synthesizes for legacy files.
extension KDBXReader {
    /// Parse a KDBX 3.0 / 3.1 file. Returns the same ``KDBXContent``
    /// shape as the 4.x path:
    ///
    /// - `header.formatVersion` carries the on-disk version (3.0 or 3.1) so
    ///   callers can decide whether to surface a migration warning.
    /// - `header.kdfParameters` is synthesized as `.aes(...)` from the
    ///   `TransformSeed` + `TransformRounds` outer-header fields.
    /// - `innerHeader` is synthesized: Salsa20 + the `ProtectedStreamKey`
    ///   from the outer header, plus the binary pool harvested from the
    ///   XML `<Meta><Binaries>` element.
    mutating func parse3x(
        unlockData: UnlockData?,
        retainsXMLForDiagnostics: Bool,
        maxDecompressedPayloadSize: Int,
        kdfLimits: KDFParameterLimits
    ) throws(KDBXReader.Error) -> KDBXContent {
        // MARK: 1. Cleartext header

        let header: Header
        let payloadKeys: Header3xReader.PayloadKeys
        let headerLength: Int
        do {
            var reader = Header3xReader(data: data)
            (header, payloadKeys, headerLength) = try reader.parse()
            self.header = header
        } catch {
            switch error {
            case .invalidSignature:
                throw .invalidFileSignature
            case let .unsupportedFormatVersion(major, minor):
                throw .unsupportedFormatVersion(major: major, minor: minor)
            case let .unsupportedCompression(compression):
                throw .unsupportedCompression(compression)
            case let .unsupportedEncryption(uuid):
                throw .unsupportedEncryption(uuid)
            case let .unsupportedInnerRandomStream(rawValue):
                // No dedicated public error case for legacy inner-stream
                // IDs — surface as a corrupted-header reason rather than
                // expanding the public Error surface for a path that's
                // already retired. Callers see a typed
                // `.corruptedHeader` and can present the reason verbatim.
                throw .corruptedHeader(reason: "Unsupported inner random stream ID: \(rawValue)")
            case let .corrupted(reason):
                throw .corruptedHeader(reason: reason)
            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }
        cursor.advance(by: headerLength)

        guard let unlockData else {
            // Match the 4.x contract: `parseHeader(_:)` drives the parser
            // up to this point and consumes the throw to recover the
            // captured `self.header`.
            throw .unlockDataRequired
        }

        // MARK: 2. KDF — derive unlock key from credentials + AES-KDF parameters

        let unlockKey: SecureBytes
        do throws(UnlockDataError) {
            unlockKey = try unlockData.computeUnlockKey(kdfParameters: header.kdfParameters, limits: kdfLimits)
        } catch {
            switch error {
            case let .unsupportedKDF(uuid):
                throw .unsupportedKDF(uuid)
            case let .kdfFailed(reason):
                throw .corruptedHeader(reason: "KDF rejected header parameters: \(reason)")
            case let .unsupportedKDFParameter(name):
                // Unreachable in 3.x: AES-KDF doesn't take Argon2 K/A.
                // Still required for switch exhaustiveness.
                throw .corruptedHeader(reason: "Unsupported KDF parameter: \(name)")
            case let .kdfParametersOutOfRange(reason):
                throw .kdfParametersOutOfRange(reason: reason)
            }
        }

        // MARK: 3. AES-CBC decrypt the body

        // The encrypted body is everything after the header. Unlike 4.x,
        // there's no SHA / HMAC trailer to skip — the body starts
        // immediately.
        let ciphertext = data.subdata(in: cursor.position..<data.endIndex)

        let mainContentKey: SecureBytes = MainKey.make(masterSalt: header.masterSalt, unlockKey: unlockKey)
        // KDBX 3.x has no HMAC — wrong credentials produce garbage that
        // fails the StreamStartBytes check below. AES-CBC decrypt itself
        // can throw on invalid PKCS7 padding (which a wrong key often
        // triggers), so surface that as wrongCredentials.
        let keyData = mainContentKey.withUnsafeBytes { keyPtr in
            Data(keyPtr.bindMemory(to: UInt8.self))
        }
        var plaintext: Data
        do {
            plaintext = try AES256CBC.decrypt(iv: header.encryptionNonce, cipherText: ciphertext, keyData)
        } catch {
            throw KDBXReader.Error.wrongCredentials
        }

        // MARK: 4. StreamStartBytes — the 3.x equivalent of wrong-credentials detection

        guard plaintext.count >= 32 else {
            // Decrypted body shorter than the 32-byte sentinel — the file is
            // truncated. Treat as wrong credentials only if the prefix
            // matches; otherwise surface corruption.
            throw .corruptedHeader(reason: "Decrypted body shorter than StreamStartBytes")
        }
        let streamStart = plaintext.prefix(32)
        // Constant-time compare: the StreamStartBytes value is in the
        // cleartext header, so it is not itself a secret. The plaintext
        // bytes we just decrypted *are* derived from the user's key,
        // though, and short-circuit comparison on key-derived material is
        // a timing oracle in the same shape as the 4.x HMAC compare.
        if !ConstantTime.equals(Data(streamStart), payloadKeys.streamStartBytes) {
            throw .wrongCredentials
        }
        plaintext.removeFirst(32)

        // MARK: 5. Hashed block stream

        let blockStreamData: Data
        do {
            blockStreamData = try HashedBlockStreamReader.decode(plaintext)
        } catch {
            switch error {
            case let .blockHashMismatch(blockIndex):
                throw .corruptedHMAC(reason: "Block \(blockIndex) hash mismatch (KDBX 3.x SHA-256)")
            case .unterminatedStream:
                throw .corruptedXML(reason: "Hashed block stream missing terminator")
            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }

        // MARK: 6. Decompress

        var xmlBytes = blockStreamData
        switch header.compressionAlgorithm {
        case .none:
            break
        case .gzip:
            do {
                xmlBytes = try GzipStreamReader.decompress(xmlBytes, maxOutputBytes: maxDecompressedPayloadSize)
            } catch ZlibError.outputTooLarge {
                throw .decompressedPayloadTooLarge(limit: maxDecompressedPayloadSize)
            } catch {
                throw .corruptedXML(reason: "Failed to decompress: \(error)")
            }
        }

        // MARK: 7. Synthesize the InnerHeader

        // 3.x has no inner header on disk. Build one in-memory so
        // ``KDBXContent`` keeps a uniform shape across formats and the
        // existing keystream + binary-pool plumbing stays unchanged.
        // The XML reader fills in the binary pool below; allocate now
        // so the synthesized inner header is the single source of truth.
        var innerHeader = InnerHeader(
            encryptionAlgorithm: .Salsa20,
            encryptionKey: payloadKeys.protectedStreamKey,
            binaryContent: []
        )

        // MARK: 8. XML parse

        guard let xmlDocument = String(validating: xmlBytes, as: UTF8.self) else {
            throw .corruptedXML(reason: "Failed to parse the XML document as a utf8 string")
        }
        self.xmlDocument = xmlDocument

        let database: KDBX
        var parserWarnings: [String] = []
        let collectedBinaryPool: [InnerHeader.BinaryContent]
        let keystreamSource: KeystreamSource
        do {
            keystreamSource = try innerHeader.makeKeystreamSource()
        } catch {
            throw .corruptedInnerHeader(reason: "Inner-stream key derivation failed: \(error)")
        }
        do {
            let xmlDocumentReader = try XMLDocumentReader(
                xmlDocument: xmlDocument,
                keystreamSource: keystreamSource,
                dateFormat: .iso8601
            )
            database = try xmlDocumentReader.parse()
            parserWarnings = xmlDocumentReader.collectedWarnings
            collectedBinaryPool = xmlDocumentReader.inlineBinaryPool
        } catch {
            switch error {
            case let .corrupted(reason):
                throw .corruptedXML(reason: reason)
            }
        }

        innerHeader.binaryContent = collectedBinaryPool
        self.innerHeader = innerHeader

        // Mirror the 4.x parse contract: release the XML buffer unless
        // the caller specifically asked for it.
        if !retainsXMLForDiagnostics {
            self.xmlDocument = nil
        }

        return .init(
            database: database,
            header: header,
            innerHeader: innerHeader,
            parserWarnings: parserWarnings,
            legacyFormatNotice: .willMigrate(from: header.formatVersion)
        )
    }
}
