//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// Errors raised while ingesting a user-supplied key file. Surfaced
/// from the keyfile-accepting `UnlockData` initialisers. Distinct from
/// ``UnlockDataError`` because credential ingestion and KDF derivation
/// are independent failure modes, and keeping them separate avoids
/// contaminating every `UnlockDataError` switch site with a case that
/// can't occur there.
public enum KeyFileError: Error, Sendable, Equatable {
    /// The key file claims to be an XML v2.0 KeePass key file (it
    /// carries a `Hash` attribute on the `<Data>` element) but the
    /// SHA-256 of the decoded bytes does not match the truncated hash
    /// in that attribute. KeePass/KeePassXC reject such files outright;
    /// continuing with the decoded bytes would silently use a key
    /// derived from corrupted material and surface as "wrong password"
    /// rather than the real cause.
    case checksumMismatch
}

/// Errors raised while turning a user-provided key into a vault unlock key.
public enum UnlockDataError: Error, Sendable, Equatable {
    /// The KDF identified by this UUID isn't implemented by KDBXKit. The
    /// reader records the UUID from the file's KDF parameters so the caller
    /// can describe what the file used.
    case unsupportedKDF(UUID)

    /// The KDF rejected the parameters supplied by the file's header (for
    /// Argon2: memory/iterations/parallelism out of range, salt too short
    /// or too long, etc.). The header validator rejects out-of-range values
    /// upstream, so this signals either a crafted/malformed file or a
    /// validator/KDF mismatch that should be reported as a bug.
    case kdfFailed(reason: String)

    /// The file's KDFParameters carry a recognised KDF (Argon2d/Argon2id)
    /// but include an optional Argon2 parameter — secret key `K` or
    /// associated data `A` — that this build does not forward to the
    /// hash function. Failing here is better than silently deriving the
    /// wrong key and surfacing as "wrong password". Such files are
    /// vanishingly rare in practice; the upstream KDBX format
    /// documentation does not mention `K` or `A` in the standard
    /// parameter set.
    case unsupportedKDFParameter(name: String)

    /// The KDF parameters in the header exceed the caller's
    /// ``KDFParameterLimits`` policy. Thrown before any KDF allocation/compute,
    /// closing the denial-of-service vector where a crafted file declares an
    /// absurd Argon2 memory or iteration cost.
    case kdfParametersOutOfRange(reason: String)
}

/// Container for the key data needed to unlock a `.kdbx` file.
///
/// KDBX derives the unlock key in two passes:
///
/// 1. **Pre-hash.** `R = SHA-256(SHA-256(password.utf8) || keyFile)`.
///    Components are optional: at least one of password or key file must be
///    provided. (Key-provider plugins and Windows DPAPI keys from the spec
///    aren't currently supported.)
/// 2. **KDF.** `T = KDF(R)` where the KDF and its parameters are stored in
///    the file header. Supported: AES-KDF, Argon2d, Argon2id.
///
/// `UnlockData` performs step 1 at init and **discards the cleartext
/// password buffer immediately**. Swift `String` can't be securely zeroed,
/// so keeping the password around longer than necessary is a real concern
/// for a password manager — by storing only the 32-byte pre-hash internally
/// we shorten the cleartext lifetime to the init call frame.
///
/// `UnlockData` is `Sendable`, so it can be passed across actor boundaries
/// (e.g. from the UI thread to a detached writer task).
///
/// https://keepass.info/help/kb/kdbx.html#keys
public struct UnlockData: Sendable {
    /// The 32-byte pre-hash R, held in zero-on-deinit storage. Combined with
    /// the file's KDF salt + parameters to produce the unlock key. Stored as
    /// `SecureBytes` rather than `Data` so the buffer is `mlock`'d and the
    /// bytes are zeroed when the last reference releases.
    let keyData: SecureBytes

    /// Build an unlock from a master password alone.
    public init(masterPassword: String) {
        // No key file → no validation can fail. Use the throwing
        // helper with `try!` because the only failure mode lives on
        // the key-file path, which we're skipping.
        keyData = try! Self.makeKeyData(password: masterPassword, keyFile: nil)
    }

    /// Build an unlock from a master password plus an optional key file.
    ///
    /// Throws ``KeyFileError`` when the key file is structurally an
    /// XML v2.0 KeePass key file but its embedded checksum does not
    /// match the decoded bytes.
    public init(masterPassword: String, keyFile: Data?) throws(KeyFileError) {
        keyData = try Self.makeKeyData(password: masterPassword, keyFile: keyFile)
    }

    /// Build an unlock from a key file alone (no password).
    ///
    /// Throws ``KeyFileError`` on the same conditions as
    /// ``init(masterPassword:keyFile:)``.
    public init(keyFile: Data) throws(KeyFileError) {
        keyData = try Self.makeKeyData(password: nil, keyFile: keyFile)
    }

    /// Build an unlock from already-derived key data — the 32-byte
    /// SHA-256 pre-hash `R` from the KDBX spec.
    ///
    /// Use this when restoring an `UnlockData` from a side channel —
    /// e.g. Keychain-backed biometric unlock — where the caller stored
    /// the pre-hash on first unlock and is now rehydrating without
    /// re-prompting for the master password. The pre-hash is not the
    /// master password, but it does grant the same unlock authority,
    /// so callers MUST protect it appropriately (Keychain access
    /// control, biometric gate, etc.).
    ///
    /// - Precondition: `rawKeyData.count == 32`.
    public init(rawKeyData: Data) {
        precondition(rawKeyData.count == 32, "Raw key data must be SHA-256-sized (32 bytes)")
        keyData = SecureBytes(rawKeyData)
    }

    /// Direct read access to the 32-byte pre-hash. Used by callers who
    /// need to hand the key material to an external secure store (e.g.
    /// Keychain) — exactly the inverse of `init(rawKeyData:)`.
    ///
    /// The returned `SecureBytes` is the live buffer; do not extend its
    /// lifetime beyond the persistence call.
    public var keyDataBytes: SecureBytes { keyData }

    /// Constant-time equality against another `UnlockData`. Use this in
    /// any re-authentication path where the caller already holds the
    /// authoritative unlock and wants to verify a freshly-typed master
    /// password produces the same pre-hash — biometric enrollment is
    /// the obvious case.
    ///
    /// Constant-time matters less here than at HMAC comparison time
    /// (no remote attacker can measure the wall-clock of an in-process
    /// compare), but using the wrong tool is still the wrong tool.
    public func matches(_ other: UnlockData) -> Bool {
        // SecureBytes.== is already a constant-time compare over the
        // in-place mlocked buffers — no copies into unzeroed Data.
        keyData == other.keyData
    }

    /// Run the KDF identified by `kdfParameters` against this unlock's key
    /// data, producing the 32-byte transformed key `T` from the KDBX spec.
    /// Throws `UnlockDataError.unsupportedKDF` when the KDF UUID in the file
    /// isn't one of AES-KDF / Argon2d / Argon2id.
    ///
    /// Public so callers can time the same code path the real unlock
    /// uses — useful for showing an estimated unlock time when the
    /// user is configuring KDF parameters for a fresh vault.
    public func computeUnlockKey(
        kdfParameters: KDFParameters,
        limits: KDFParameterLimits = .default
    ) throws(UnlockDataError) -> SecureBytes {
        if let reason = limits.breach(for: kdfParameters) {
            throw .kdfParametersOutOfRange(reason: reason)
        }
        switch kdfParameters {
        case let .aes(params, _):
            return AESKDF.derive(salt: params.salt, rounds: params.rounds, keyData)

        case let .argon2d(params, additional):
            try Self.rejectUnsupportedArgon2Extras(additional)
            do {
                return try Argon2KDF.argon2d(password: keyData, params: params)
            } catch {
                throw UnlockDataError.kdfFailed(reason: "\(error)")
            }

        case let .argon2id(params, additional):
            try Self.rejectUnsupportedArgon2Extras(additional)
            do {
                return try Argon2KDF.argon2id(password: keyData, params: params)
            } catch {
                throw UnlockDataError.kdfFailed(reason: "\(error)")
            }

        case let .unknown(uuid):
            throw .unsupportedKDF(uuid)
        }
    }

    /// Reject Argon2 KDFParameters that declare a non-empty secret key
    /// `K` or associated data `A`. We call `argon2id_hash_raw` /
    /// `argon2d_hash_raw`, neither of which accepts those inputs; a
    /// file using them would silently derive a wrong key and surface
    /// as "wrong password". Surfacing the limitation explicitly is the
    /// honest answer until we wire `argon2_ctx`.
    private static func rejectUnsupportedArgon2Extras(_ additional: VariantDictionary) throws(UnlockDataError) {
        for key in ["K", "A"] {
            guard let value = additional[key] else { continue }
            // Per Argon2 RFC 9106 K and A are byte arrays. Be tolerant
            // of other variant types — any non-empty value with these
            // keys is a parameter we don't honour.
            switch value {
            case let .bytes(data) where !data.isEmpty:
                throw .unsupportedKDFParameter(name: key)
            case .bytes:
                // Empty K/A is semantically identical to absent.
                continue
            default:
                throw .unsupportedKDFParameter(name: key)
            }
        }
    }

    private static func makeKeyData(password: String?, keyFile: Data?) throws(KeyFileError) -> SecureBytes {
        // R = SHA-256( SHA-256(password.utf8) || normalized(keyFile) )
        var hasher = SHA256()
        if let password {
            // String → UTF-8 cannot fail.
            let utf8 = password.data(using: .utf8)!
            hasher.update(data: utf8.sha256())
        }
        if let keyFile {
            hasher.update(data: try normalizeKeyFile(keyFile))
        }
        return SecureBytes(Data(hasher.finalize()))
    }

    /// Reduce a user-provided key file to the 32-byte contribution that
    /// feeds into the unlock-key derivation.
    ///
    /// Per the KDBX spec (https://keepass.info/help/kb/keyfile.html):
    ///
    /// - XML keyfile v1 (`<KeyFile><Key><Data>HEX</Data></Key></KeyFile>`):
    ///   decode the inner hex to 32 bytes.
    /// - XML keyfile v2 (`<KeyFile><Key><Data Hash="XXXXXXXX">BASE64</Data></Key></KeyFile>`):
    ///   decode the base64 to 32 bytes; verify the optional `Hash` attribute
    ///   against the first 4 bytes of SHA-256 of the decoded bytes.
    /// - Exactly 32 bytes: use those raw bytes (v1 binary keyfile).
    /// - Exactly 64 ASCII hex characters: decode the hex to 32 bytes
    ///   (legacy hex keyfile).
    /// - Any other file: SHA-256 hash of the entire file (arbitrary binary
    ///   — what KeePassXC's CLI generates by default).
    static func normalizeKeyFile(_ data: Data) throws(KeyFileError) -> Data {
        // XML keyfile? Detect by a small prefix scan so we don't pay full
        // XML-parse cost on raw binary files.
        if looksLikeXMLKeyFile(data), let extracted = try parseXMLKeyFile(data) {
            return extracted
        }
        // v1 raw 32-byte keyfile.
        if data.count == 32 {
            return data
        }
        // v1 hex keyfile (64 ASCII hex chars).
        if data.count == 64, let decoded = decodeHexKeyFile(data) {
            return decoded
        }
        // Arbitrary binary file: SHA-256 of the contents.
        return Data(SHA256.hash(data: data))
    }

    /// True if `data` plausibly starts with an XML KeyFile document.
    /// Cheaper than a full parse: only checks the first ~256 bytes for
    /// `<KeyFile`.
    private static func looksLikeXMLKeyFile(_ data: Data) -> Bool {
        // KeePass XML keyfiles are tiny (under 1 KB). Files larger than
        // 8 KB are almost certainly arbitrary binary that shouldn't go
        // through XML parsing.
        guard data.count < 8192 else { return false }
        let prefix = data.prefix(256)
        guard let head = String(data: prefix, encoding: .utf8) else { return false }
        return head.contains("<KeyFile")
    }

    /// Parse a KeePass XML keyfile (v1 or v2) and return the 32-byte hash.
    /// Returns nil on any structural parse / decode failure so the
    /// caller can fall through to the next strategy. Throws
    /// ``KeyFileError/checksumMismatch`` when the file is unambiguously
    /// an XML v2 key file (the `<Data>` element carries a `Hash`
    /// attribute) but the embedded hash does not match the SHA-256 of
    /// the decoded bytes — matching KeePass/KeePassXC behaviour, which
    /// reject such files rather than silently using the corrupted
    /// material.
    private static func parseXMLKeyFile(_ data: Data) throws(KeyFileError) -> Data? {
        guard let xml = String(data: data, encoding: .utf8) else { return nil }
        guard let document = try? Document(string: xml) else { return nil }
        guard let root = document.root, root.name == "KeyFile" else { return nil }

        // Find <Key><Data>...</Data></Key>.
        let key = root.children.first { $0.name == "Key" }
        guard let dataNode = key?.children.first(where: { $0.name == "Data" }) else { return nil }

        // Read the text content (concatenate text children, strip whitespace).
        var text = ""
        for child in dataNode.children where child.kind == .text {
            text += child.value
        }
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        let hashAttribute = dataNode.attributes.first { name, _ in name == "Hash" }?.1
        let isV2 = hashAttribute != nil

        let decoded: Data?
        if isV2 {
            // v2: base64-encoded 32 bytes.
            decoded = Data(base64Encoded: text, options: .ignoreUnknownCharacters)
        } else {
            // v1: hex-encoded 32 bytes (KeePass historical format). Some
            // producers also write base64 — try hex first, then base64
            // as a fallback.
            let stripped = text.filter { !$0.isWhitespace }
            if stripped.count == 64,
               let hex = decodeHexKeyFile(Data(stripped.utf8))
            {
                decoded = hex
            } else {
                decoded = Data(base64Encoded: stripped, options: .ignoreUnknownCharacters)
            }
        }

        guard let bytes = decoded, bytes.count == 32 else { return nil }

        // v2 integrity check. The `Hash` attribute carries the first 4
        // bytes of SHA-256(decoded), hex-encoded. KeePass and KeePassXC
        // both reject the file on mismatch; do the same.
        if let hashAttribute {
            let expectedFirstFour = bytes.sha256().prefix(4)
            guard let attributeBytes = hexDecode(hashAttribute), attributeBytes.count >= 4 else {
                // Hash attribute is present but not parseable as hex →
                // structurally invalid v2 key file.
                throw .checksumMismatch
            }
            if !ConstantTime.equals(Data(expectedFirstFour), attributeBytes.prefix(4)) {
                throw .checksumMismatch
            }
        }

        return bytes
    }

    /// Hex-decode an ASCII hex string into a `Data`. Whitespace is
    /// tolerated, case is not significant. Any non-ASCII or non-hex
    /// character, or an odd-length input, returns nil.
    private static func hexDecode(_ string: String) -> Data? {
        let stripped = string.filter { !$0.isWhitespace }
        guard stripped.count.isMultiple(of: 2) else { return nil }
        var out = Data(capacity: stripped.count / 2)
        var iter = stripped.unicodeScalars.makeIterator()
        while let hi = iter.next(), let lo = iter.next() {
            guard hi.value < 128, lo.value < 128,
                  let hiVal = hexValue(UInt8(hi.value)),
                  let loVal = hexValue(UInt8(lo.value))
            else {
                return nil
            }
            out.append(UInt8(hiVal << 4 | loVal))
        }
        return out
    }

    /// Decode a 64-byte ASCII hex string into 32 bytes. Returns nil if any
    /// byte is not an ASCII hex digit.
    private static func decodeHexKeyFile(_ data: Data) -> Data? {
        precondition(data.count == 64)
        var out = Data(capacity: 32)
        var i = data.startIndex
        while i < data.endIndex {
            guard let hi = hexValue(data[i]), let lo = hexValue(data[i + 1]) else {
                return nil
            }
            out.append(UInt8(hi << 4 | lo))
            i = i.advanced(by: 2)
        }
        return out
    }

    private static func hexValue(_ b: UInt8) -> UInt8? {
        switch b {
        case 0x30...0x39: return b - 0x30 // '0'-'9'
        case 0x41...0x46: return b - 0x41 + 10 // 'A'-'F'
        case 0x61...0x66: return b - 0x61 + 10 // 'a'-'f'
        default: return nil
        }
    }
}
