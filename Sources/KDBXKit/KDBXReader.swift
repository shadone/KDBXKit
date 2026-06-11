//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// Parser for the `.kdbx` file format.
///
/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.                           <<- parses
/// 2. SHA-256 hash of the header.       <<- validates
/// 3. HMAC-SHA-256 hash of the header.  <<- validates
/// 4. In HMAC-protected block stream:   <<- parses
///    a. Encrypted:                     <<- decrypts
///       i. Compressed (optional):      <<- decompresses
///          - Inner header.             <<- parses & returns binary content
///          - XML document.             <<- returns
/// ```
///
/// https://keepass.info/help/kb/kdbx.html
public struct KDBXReader: Sendable {
    /// Errors thrown by `KDBXReader.parse`.
    public enum Error: Swift.Error, Sendable, Equatable {
        // MARK: - Caller errors

        /// `parse(unlockData: nil)` was used — fine if you only wanted to
        /// inspect the file header via `reader.header`, but you can't get a
        /// full `KDBXContent` without credentials.
        ///
        /// **Note:** If you want a header-only inspect, prefer
        /// `KDBXReader.parseHeader(_:)` which doesn't require a try/catch
        /// dance.
        case unlockDataRequired

        /// The provided key data (password and/or key file) does not match.
        /// Triggered when the HMAC of the header — computed with the user's
        /// derived key — disagrees with the HMAC stored in the file.
        case wrongCredentials

        // MARK: - Format/feature support

        /// KDBX file format major.minor version isn't supported by KDBXKit.
        /// KDBXKit reads 3.1, 4.0, and 4.1 (see ``Header/FormatVersion/supported``);
        /// 3.0 and unknown versions throw this error.
        case unsupportedFormatVersion(major: UInt16, minor: UInt16)

        /// The file's encryption algorithm UUID isn't supported. Currently
        /// supported: AES-256-CBC and ChaCha20.
        case unsupportedEncryption(UUID)

        /// The file's compression-algorithm code isn't supported. Currently
        /// supported: `0` (none) and `1` (gzip).
        case unsupportedCompression(UInt32)

        /// The file's key derivation function UUID isn't supported. Currently
        /// supported: AES-KDF, Argon2d, Argon2id.
        case unsupportedKDF(UUID)

        // MARK: - Corruption

        /// File signature bytes don't match the KDBX magic — almost always
        /// because the input isn't a KDBX file at all.
        case invalidFileSignature

        /// The file header (cleartext) is structurally invalid.
        case corruptedHeader(reason: String)

        /// The header's KDF parameters exceed the limits the caller passed via
        /// `kdfLimits` (defaulting to ``KDFParameterLimits/default``). Surfaced
        /// before any KDF runs — a defense against KDF-bomb denial of service.
        case kdfParametersOutOfRange(reason: String)

        /// The header's SHA-256 digest stored alongside it doesn't match the
        /// header we read — suggests on-disk corruption rather than tampering
        /// (the SHA-256 isn't a MAC).
        case corruptedHeaderDigest

        /// An HMAC of an encrypted block doesn't match its expected value.
        /// Indicates the encrypted stream has been tampered with or the file
        /// is truncated.
        case corruptedHMAC(reason: String)

        /// The inner header (binary attachment table etc.) is structurally
        /// invalid after decryption.
        case corruptedInnerHeader(reason: String)

        /// The decrypted XML payload couldn't be parsed.
        case corruptedXML(reason: String)

        /// The compressed payload, after gzip inflation, exceeded
        /// `KDBXReader.maxDecompressedPayloadSize`. Defensive cap against
        /// pathological / corrupt files that would otherwise allocate
        /// unbounded amounts of memory. The HMAC is verified before
        /// decompression, so this is a robustness signal rather than an
        /// attack indicator.
        case decompressedPayloadTooLarge(limit: Int)

        // MARK: - I/O

        /// Read past the end of the input data.
        case unexpectedEOF
    }

    /// Maximum acceptable size of the gzip-decompressed payload, in bytes.
    /// Realistic vaults are single-digit MB even with attachments; this is a
    /// generous defensive ceiling, not a soft limit. Reading a file whose
    /// decompressed payload exceeds this throws `.decompressedPayloadTooLarge`.
    public static let maxDecompressedPayloadSize = 256 * 1024 * 1024

    let data: Data
    /// Cursor over `data` driving the sequential token reads (header digest,
    /// HMAC, block stream). `data` itself is still held for the whole-buffer
    /// operations that aren't position-relative — the header-bytes digest and
    /// the version peek.
    var cursor: ByteCursor

    /// The header of the `.kdbx` file.
    ///
    /// - note: This is for debug purposes, for accessing the value even if the parsing failed due to e.g. invalid master password.
    ///
    /// Setter is `internal(set)` so the per-format pipeline extensions
    /// (`parse3x` for legacy 3.x, the inline 4.x path here) can write
    /// it. From outside the module it remains read-only.
    public internal(set) var header: Header?

    /// The inner header of the `.kdbx` file.
    ///
    /// - note: This is for debug purposes, for accessing the value even if the parsing failed due to e.g. corrupted content.
    public internal(set) var innerHeader: InnerHeader?

    /// The raw decrypted XML document (with the inner-stream-cipher protected
    /// strings still base64-encoded — those are decrypted further into the
    /// returned `KDBXContent`).
    ///
    /// **Released on success.** Unprotected fields (Title, URL, Notes) are
    /// plaintext in this `String`; keeping it around for the reader's
    /// lifetime would mean every unlocked vault retains its entire metadata
    /// as a long-lived Swift `String` on the heap (where we can't zero it).
    /// On a successful parse, `parse(unlockData:)` clears this property
    /// before returning. It's retained only when:
    ///
    /// - parse fails after decryption (helps diagnose the XML-level failure)
    /// - the caller used `parse(unlockData:retainsXMLForDiagnostics: true)`
    public internal(set) var xmlDocument: String?

    /// The size of the each blocks of the HMAC-protected block stream.
    ///
    /// - note: This is for debug purposes.
    public internal(set) var blockSizes: [Int32] = []

    public init(_ data: Data) {
        self.data = data
        cursor = ByteCursor(data)
    }

    // MARK: - One-shot static API

    /// Parse a complete KDBX file in one call. The common case.
    ///
    /// If you also want access to the intermediate state when parsing fails
    /// (e.g. the parsed `Header` after a wrong-credentials error so you can
    /// show the user the file name + format), construct a `KDBXReader`
    /// directly and call the mutating `parse(unlockData:)` instead.
    ///
    /// - Parameter kdfLimits: Caller-supplied ceiling on KDF cost (memory, iterations,
    ///   parallelism, AES-KDF rounds). Defaults to ``KDFParameterLimits/default``. Pass a
    ///   tighter policy in untrusted contexts to defend against KDF-bomb payloads. Enforced
    ///   before the KDF runs; out-of-policy parameters throw ``Error/kdfParametersOutOfRange(reason:)``.
    public static func parse(
        _ data: Data,
        unlockData: UnlockData,
        kdfLimits: KDFParameterLimits = .default
    ) throws(Error) -> KDBXContent {
        var reader = KDBXReader(data)
        return try reader.parse(unlockData: unlockData, kdfLimits: kdfLimits)
    }

    /// Inspect a KDBX file's header without unlocking it. No password / key
    /// file needed. Validates the file signature, format version, and header
    /// SHA-256 — anything beyond that lives in the encrypted body.
    public static func parseHeader(_ data: Data) throws(Error) -> Header {
        var reader = KDBXReader(data)
        do throws(Error) {
            _ = try reader.parse(unlockData: nil)
            // parse(unlockData: nil) always throws .unlockDataRequired after
            // the header is captured. Reaching here means the parser shape
            // changed — defensive throw rather than silent return.
            throw Error.corruptedHeader(reason: "Reader unexpectedly returned without unlock data")
        } catch {
            // error is typed as KDBXReader.Error here.
            if case .unlockDataRequired = error {
                // Expected path: header was parsed, parser stopped waiting
                // for credentials.
            } else {
                throw error
            }
        }
        guard let header = reader.header else {
            throw .corruptedHeader(reason: "Reader did not capture the header")
        }
        return header
    }

    /// Reject a header whose format version KDBXKit cannot open.
    ///
    /// Single, header-only restatement of the version gate the read
    /// pipeline already enforces inside the route-specific readers
    /// (``Header/FormatVersion/supported``). `parse` / `parse3x` reject
    /// unsupported versions during the header walk, so a full unlock
    /// never needs this; it exists for callers that inspect a header via
    /// ``parseHeader(_:)`` and then decide whether to proceed *without*
    /// paying the KDF — peek paths. Using it (rather than an inline
    /// `major == 4` test) keeps the supported-format rule in one place,
    /// so peek can't drift from what `parse` actually accepts.
    public static func validateSupportedFormat(_ header: Header) throws(Error) {
        guard header.formatVersion.isSupported else {
            throw .unsupportedFormatVersion(
                major: header.formatVersion.major,
                minor: header.formatVersion.minor
            )
        }
    }

    // MARK: Read <token> helpers

    /// Read the format major version (without advancing `pos`). Returns
    /// `0` for files too short to contain a version header — the caller
    /// then falls through to the regular 4.x parser, which surfaces the
    /// same input as either `invalidFileSignature` or `unexpectedEOF`.
    ///
    /// 12-byte prefix layout: signature1 (UInt32 LE), signature2 (UInt32
    /// LE), version (UInt32 LE: low 16 = minor, high 16 = major).
    private func peekFormatMajor() throws(Error) -> UInt16 {
        guard data.count >= 12 else { return 0 }
        let versionData = data.subdata(in: data.startIndex.advanced(by: 8)..<data.startIndex.advanced(by: 12))
        guard let raw = versionData.asUInt32LE() else { return 0 }
        return UInt16(raw >> 16)
    }

    private mutating func readInt32() throws(Error) -> Int32 {
        do { return try cursor.readInt32LE() } catch { throw .unexpectedEOF }
    }

    private mutating func readData(length: Int) throws(Error) -> Data {
        do { return try cursor.readData(length: length) } catch { throw .unexpectedEOF }
    }

    // MARK: Public API

    /// - Parameter kdfLimits: Caller-supplied ceiling on KDF cost (memory, iterations,
    ///   parallelism, AES-KDF rounds). Defaults to ``KDFParameterLimits/default``. Pass a
    ///   tighter policy in untrusted contexts to defend against KDF-bomb payloads. Enforced
    ///   before the KDF runs; out-of-policy parameters throw ``Error/kdfParametersOutOfRange(reason:)``.
    public mutating func parse(
        unlockData: UnlockData?,
        retainsXMLForDiagnostics: Bool = false,
        maxDecompressedPayloadSize: Int = KDBXReader.maxDecompressedPayloadSize,
        kdfLimits: KDFParameterLimits = .default
    ) throws(Error) -> KDBXContent {
        // Peek the format major version before committing to a header
        // parser. KDBX 3.x and 4.x diverge starting at the first header
        // field (UInt16 vs UInt32 lengths), so the two readers cannot
        // share state beyond the 12-byte signature+version prefix.
        let formatMajor = try peekFormatMajor()
        if formatMajor == 3 {
            return try parse3x(
                unlockData: unlockData,
                retainsXMLForDiagnostics: retainsXMLForDiagnostics,
                maxDecompressedPayloadSize: maxDecompressedPayloadSize,
                kdfLimits: kdfLimits
            )
        }

        let header: Header
        let headerLength: Int

        // MARK: 1. Header

        do {
            var reader = HeaderReader(data: data)
            (header, headerLength) = try reader.parse()
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
            case let .corrupted(reason):
                throw .corruptedHeader(reason: reason)
            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }

        // Move past the header to the next token
        cursor.advance(by: headerLength)

        // MARK: 2. SHA-256 of the header

        // calculate SHA256 of the header
        let headerData = Data(data[..<headerLength])
        let headerSHA256 = headerData.sha256()

        let headerSHA256FromFile = try readData(length: 32)
        // SHA-256 here is an integrity check — not a secret comparison — so a
        // short-circuiting `!=` would technically be fine. Using constant-time
        // anyway so we don't have two compare conventions in the same parser.
        if !ConstantTime.equals(headerSHA256, headerSHA256FromFile) {
            throw Error.corruptedHeaderDigest
        }

        guard let unlockData else {
            // Shortcircuit early if no credentials were provided — caller can
            // still inspect `self.header`.
            throw .unlockDataRequired
        }

        // MARK: 3. HMAC-SHA256 of the header

        // calculate HMAC-SHA256 of the header
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
                throw .corruptedHeader(reason: "Unsupported KDF parameter: \(name)")
            case let .kdfParametersOutOfRange(reason):
                throw .kdfParametersOutOfRange(reason: reason)
            }
        }

        let headerKey = HMACProtectedBlockStream.keyForHeader(masterSalt: header.masterSalt, unlockKey: unlockKey)

        let headerHMACSHA256 = headerData.hmacSha256(key: headerKey)
        let headerHMACSHA256FromFile = try readData(length: 32)
        // HMAC compare *must* be constant-time — leaking how many leading
        // bytes of an attacker's guess matched is the classic timing oracle.
        if !ConstantTime.equals(headerHMACSHA256, headerHMACSHA256FromFile) {
            throw Error.wrongCredentials
        }

        // MARK: 4. Parse HMAC-protected block stream

        var blockIndex: UInt64 = 0
        var payload = Data(capacity: data.count)
        while true {
            let hmacFromFile = try readData(length: 32)
            let size = try readInt32()
            let block = try readData(length: Int(size))

            // Authenticate every block, including the size-0 sentinel that
            // terminates the stream. Verifying the sentinel binds the
            // "this is the end" signal to the unlock key and blocks
            // truncation attacks where an attacker swaps an interior
            // block for a size-0 marker — the substituted marker won't
            // carry a valid HMAC at the next blockIndex.
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
                throw Error.corruptedHMAC(reason: "Block \(blockIndex) HMAC mismatch")
            }

            // The HMAC-protected block stream is terminated by an output block for an empty
            // input block (i.e. M empty, s = 0).
            if size == 0 {
                assert(block.isEmpty)
                break
            }

            blockSizes.append(size)
            payload.append(block)

            blockIndex += 1
        }

        // MARK: 4.a Decrypt payload

        let mainContentKey: SecureBytes = MainKey.make(masterSalt: header.masterSalt, unlockKey: unlockKey)

        switch header.encryptionAlgorithm {
        case .AES256CBC:
            // HMAC has already been verified above, so the ciphertext must be
            // well-formed (block-aligned, valid PKCS7 padding). A failure here
            // would indicate a swift-crypto bug, not file corruption.
            let keyData = mainContentKey.withUnsafeBytes { keyPtr in
                Data(keyPtr.bindMemory(to: UInt8.self))
            }
            do {
                payload = try AES256CBC.decrypt(iv: header.encryptionNonce, cipherText: payload, keyData)
            } catch {
                throw Error.corruptedHMAC(reason: "AES-256-CBC decrypt failed after HMAC verification: \(error)")
            }

        case .ChaCha20:
            let chaCha20: ChaCha20
            do {
                chaCha20 = try mainContentKey.withUnsafeBytes { keyPtr in
                    try ChaCha20(key: Data(keyPtr.bindMemory(to: UInt8.self)), iv: header.encryptionNonce)
                }
            } catch {
                throw Error.corruptedHeader(reason: "Failed to initialize ChaCha20: invalid key or nonce")
            }
            payload = Data(chaCha20.decrypt(payload))
        }

        // MARK: 4.a.i Decompress payload if needed

        switch header.compressionAlgorithm {
        case .none:
            break

        case .gzip:
            // Decompress with a hard size cap so a malformed or crafted
            // payload that would inflate without bound fails mid-inflation
            // rather than after a runaway allocation.
            do {
                payload = try GzipStreamReader.decompress(payload, maxOutputBytes: maxDecompressedPayloadSize)
            } catch ZlibError.outputTooLarge {
                throw Error.decompressedPayloadTooLarge(limit: maxDecompressedPayloadSize)
            } catch {
                throw Error.corruptedXML(reason: "Failed to decompress: \(error)")
            }
        }

        // MARK: 4.a.i.1 Parse Inner Header

        let innerHeader: InnerHeader
        let innerHeaderLength: Int
        do {
            var innerHeaderReader = InnerHeaderReader(data: payload)
            (innerHeader, innerHeaderLength) = try innerHeaderReader.parse()
            self.innerHeader = innerHeader
        } catch {
            switch error {
            case let .corrupted(reason):
                throw Error.corruptedInnerHeader(reason: reason)
            case .unexpectedEOF:
                throw Error.unexpectedEOF
            }
        }

        // Remvove the inner header leaving only the XML document in the payload.
        payload.removeFirst(innerHeaderLength)

        // MARK: 4.a.i.2 XML Document

        // The remaining payload is the XML document
        guard let xmlDocument = String(validating: payload, as: UTF8.self) else {
            throw Error.corruptedXML(reason: "Failed to parse the XML document as a utf8 string")
        }
        self.xmlDocument = xmlDocument

        let database: KDBX
        var parserWarnings: [String] = []
        let keystreamSource: KeystreamSource
        do {
            keystreamSource = try innerHeader.makeKeystreamSource()
        } catch {
            // `makeKeystreamSource` only throws `InnerHeader.CryptorError`
            // today; catch-all keeps the wrapping robust against future
            // throws additions.
            throw Error.corruptedInnerHeader(reason: "Inner-stream key derivation failed: \(error)")
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
                throw .corruptedXML(reason: reason)
            }
        }

        // Plaintext XML housekeeping: release it now unless the caller
        // explicitly asked us to retain for golden tests / debugging.
        // Holding the full XML in a Swift `String` for the reader's lifetime
        // means every unprotected field stays plaintext on the heap until
        // the reader deallocates.
        if !retainsXMLForDiagnostics {
            self.xmlDocument = nil
        }

        return .init(database: database, header: header, innerHeader: innerHeader, parserWarnings: parserWarnings)
    }
}
