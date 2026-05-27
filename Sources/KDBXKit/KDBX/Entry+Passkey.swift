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
        public static let username = "KPEX_PASSKEY_USERNAME"
        public static let credentialID = "KPEX_PASSKEY_CREDENTIAL_ID"
        public static let privateKeyPEM = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
        public static let relyingParty = "KPEX_PASSKEY_RELYING_PARTY"
        public static let userHandle = "KPEX_PASSKEY_USER_HANDLE"
    }

    /// True when the entry carries the minimum fields that make it a usable
    /// passkey (relying party + credential ID + private key), independent of
    /// any cosmetic template tag, so KeePassXC-authored passkeys are
    /// recognised even if their Passie template field is unset.
    var isPasskey: Bool {
        passkeyRelyingParty != nil && passkeyCredentialID != nil && passkeyPrivateKeyPEM != nil
    }

    var passkeyRelyingParty: String? { plainPasskeyString(PasskeyField.relyingParty) }
    var passkeyUsername: String? { plainPasskeyString(PasskeyField.username) }

    /// Credential ID, base64url-decoded. Nil if absent or undecodable.
    var passkeyCredentialID: Data? {
        plainPasskeyString(PasskeyField.credentialID).flatMap(Data.fromPasskeyBase64URL)
    }

    /// User handle, base64url-decoded. Nil if absent or undecodable.
    var passkeyUserHandle: Data? {
        plainPasskeyString(PasskeyField.userHandle).flatMap(Data.fromPasskeyBase64URL)
    }

    /// PKCS#8 PEM private key as `SecureBytes`. Never materialised into a
    /// long-lived `String`; callers use the SecureBytes reveal accessor.
    var passkeyPrivateKeyPEM: SecureBytes? {
        strings.first { $0.key == PasskeyField.privateKeyPEM }?.value.bytes
    }

    private func plainPasskeyString(_ key: String) -> String? {
        guard let s = strings.first(where: { $0.key == key }) else { return nil }
        let revealed = s.value.revealedString
        return revealed.isEmpty ? nil : revealed
    }
}

extension Data {
    /// Decode base64url (RFC 4648 section 5, no padding) into bytes. Tolerates
    /// standard base64 too. Named to avoid clashing with any existing helper.
    static func fromPasskeyBase64URL(_ string: String) -> Data? {
        var s = string.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = s.count % 4
        if pad != 0 { s += String(repeating: "=", count: 4 - pad) }
        return Data(base64Encoded: s)
    }

    /// Encode as base64url with no padding (for writing in Task 2).
    func toPasskeyBase64URL() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
