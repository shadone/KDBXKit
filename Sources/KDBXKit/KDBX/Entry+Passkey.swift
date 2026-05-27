//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX.Entry {
    /// Custom-string field keys for passkeys, matching the KeePassXC
    /// convention so vaults round-trip across clients. KDBXKit knows only
    /// these field names; it does not interpret WebAuthn semantics.
    enum PasskeyField {
        /// The display name or email stored by KeePassXC as the WebAuthn userName.
        /// KeePassXC key: `KPEX_PASSKEY_USERNAME`.
        public static let username = "KPEX_PASSKEY_USERNAME"

        /// Base64url-encoded credential ID byte string assigned by the authenticator.
        /// KeePassXC key: `KPEX_PASSKEY_CREDENTIAL_ID`.
        public static let credentialID = "KPEX_PASSKEY_CREDENTIAL_ID"

        /// PKCS#8 PEM-encoded private key (EC or RSA depending on the algorithm).
        /// KeePassXC key: `KPEX_PASSKEY_PRIVATE_KEY_PEM`.
        public static let privateKeyPEM = "KPEX_PASSKEY_PRIVATE_KEY_PEM"

        /// Relying-party identifier (e.g. `"example.com"`).
        /// KeePassXC key: `KPEX_PASSKEY_RELYING_PARTY`.
        public static let relyingParty = "KPEX_PASSKEY_RELYING_PARTY"

        /// Base64url-encoded user-handle bytes assigned by the relying party.
        /// KeePassXC key: `KPEX_PASSKEY_USER_HANDLE`.
        public static let userHandle = "KPEX_PASSKEY_USER_HANDLE"
    }

    /// True when the entry carries the minimum fields that make it a usable
    /// passkey (relying party + credential ID + private key), independent of
    /// any cosmetic template tag, so KeePassXC-authored passkeys are
    /// recognised even if their Passie template field is unset.
    ///
    /// Detection is based on raw field presence, NOT on whether the credential
    /// ID decodes successfully, so an entry with a malformed base64url value is
    /// still flagged as a passkey rather than silently dropped.
    var isPasskey: Bool {
        plainPasskeyString(PasskeyField.relyingParty) != nil
            && plainPasskeyString(PasskeyField.credentialID) != nil
            && passkeyPrivateKeyPEM != nil
    }

    /// Relying-party identifier string (e.g. `"example.com"`), or nil if absent.
    var passkeyRelyingParty: String? { plainPasskeyString(PasskeyField.relyingParty) }

    /// The WebAuthn userName stored alongside the credential, or nil if absent.
    var passkeyUsername: String? { plainPasskeyString(PasskeyField.username) }

    /// Credential ID, base64url-decoded. Nil if absent or undecodable.
    var passkeyCredentialID: Data? {
        plainPasskeyString(PasskeyField.credentialID).flatMap(Data.fromPasskeyBase64URL)
    }

    /// User handle, base64url-decoded. Nil if absent or undecodable.
    var passkeyUserHandle: Data? {
        plainPasskeyString(PasskeyField.userHandle).flatMap(Data.fromPasskeyBase64URL)
    }

    /// The credential ID as stored (base64url text), without decoding. Useful for
    /// faithful display/inspection (shows the on-disk value even if malformed).
    var passkeyCredentialIDBase64URL: String? { plainPasskeyString(PasskeyField.credentialID) }

    /// The user handle as stored (base64url text), without decoding.
    var passkeyUserHandleBase64URL: String? { plainPasskeyString(PasskeyField.userHandle) }

    /// PKCS#8 PEM private key as `SecureBytes`. Never materialised into a
    /// long-lived `String`; callers use the SecureBytes reveal accessor.
    /// Returns nil when the field is absent or its byte content is empty.
    var passkeyPrivateKeyPEM: SecureBytes? {
        guard let bytes = strings.first(where: { $0.key == PasskeyField.privateKeyPEM })?.value.bytes,
              !bytes.isEmpty
        else { return nil }
        return bytes
    }

    private func plainPasskeyString(_ key: String) -> String? {
        guard let s = strings.first(where: { $0.key == key }) else { return nil }
        let revealed = s.value.revealedString
        return revealed.isEmpty ? nil : revealed
    }

    // MARK: - Setters

    /// Sets the relying-party identifier (e.g. `"example.com"`).
    /// Stored plaintext (Protected="False") to match KeePassXC.
    mutating func setPasskeyRelyingParty(_ value: String) {
        setPasskeyField(PasskeyField.relyingParty, .regular(value))
    }

    /// Sets the WebAuthn userName stored alongside the credential.
    /// Stored plaintext (Protected="False") to match KeePassXC.
    mutating func setPasskeyUsername(_ value: String) {
        setPasskeyField(PasskeyField.username, .regular(value))
    }

    /// Sets the credential ID from raw bytes. The bytes are base64url-encoded
    /// and stored with Protected="True" (`.unprotected` in memory) to match
    /// KeePassXC. The credential ID is not a private secret but is treated
    /// as sensitive on disk.
    mutating func setPasskeyCredentialID(_ data: Data) {
        setPasskeyField(PasskeyField.credentialID, .unprotected(data.toPasskeyBase64URL()))
    }

    /// Sets the user handle from raw bytes. The bytes are base64url-encoded
    /// and stored with Protected="True" (`.unprotected` in memory) to match
    /// KeePassXC.
    mutating func setPasskeyUserHandle(_ data: Data) {
        setPasskeyField(PasskeyField.userHandle, .unprotected(data.toPasskeyBase64URL()))
    }

    /// Sets the PKCS#8 PEM private key.
    ///
    /// Stored `.unprotected` so the key is inner-stream encrypted in the XML
    /// payload (`Protected="True"` on disk), matching KeePassXC. (In KDBXKit's
    /// model `.unprotected` means "encrypted on disk, plain in memory"; the
    /// `.protectedInMemory` case instead writes `ProtectInMemory="True"` with the
    /// value in CLEARTEXT on disk, which we must not do for a private key.)
    /// The caller passes a `String`, which lives briefly in the heap before being
    /// wrapped; the read accessor returns `SecureBytes`.
    mutating func setPasskeyPrivateKeyPEM(_ pem: String) {
        setPasskeyField(PasskeyField.privateKeyPEM, .unprotected(pem))
    }

    private mutating func setPasskeyField(_ key: String, _ value: KDBX.ProtectedString.Value) {
        if let idx = strings.firstIndex(where: { $0.key == key }) {
            strings[idx].value = value
        } else {
            strings.append(KDBX.ProtectedString(key: key, value: value))
        }
    }
}

/// Decode and encode base64url (RFC 4648 section 5, no padding). Tolerates
/// standard base64 in the decoder too. Named to avoid clashing with any
/// existing helper.
///
/// Both directions are `internal` (not `private`) so tests can exercise the
/// substitution logic directly at the unit level, and the passkey setters in
/// this module use `toPasskeyBase64URL()` to encode raw bytes for storage.
extension Data {
    static func fromPasskeyBase64URL(_ string: String) -> Data? {
        var s = string.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = s.count % 4
        if pad != 0 { s += String(repeating: "=", count: 4 - pad) }
        return Data(base64Encoded: s)
    }

    /// Encodes the receiver as base64url (RFC 4648 section 5) with no padding.
    func toPasskeyBase64URL() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
