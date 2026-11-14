// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
// SPDX-License-Identifier: BSD-2-Clause
import Crypto
import Foundation

/// Immutable, encrypted resident bytes with scoped plaintext access.
///
/// Each value uses its own random ChaChaPoly key and nonce. The key lives in
/// `SecureBytes`; plaintext is materialized only for an explicit reveal. This
/// reduces plaintext residence, but cannot defend a compromised process that
/// can read both ciphertext and keys. Callers remain responsible for plaintext
/// they supply or allow to escape a reveal closure.
public final class ProtectedBytes: Sendable, Equatable {
    private let key: SecureBytes
    private let sealed: ChaChaPoly.SealedBox
    /// Ciphertext for internal storage-invariant tests; never plaintext.
    var ciphertext: Data {
        sealed.ciphertext
    }

    /// Number of plaintext bytes, without decrypting them.
    public var count: Int {
        sealed.ciphertext.count
    }

    /// Whether the payload is empty, without decrypting it.
    public var isEmpty: Bool {
        count == 0
    }

    /// Encrypt a copy of `bytes`; the caller's source buffer is unchanged.
    public init(_ bytes: SecureBytes) {
        let temporaryKey = SymmetricKey(size: .bits256)
        key = temporaryKey.withUnsafeBytes { SecureBytes(copying: $0) }
        // Fixed-size generated key and automatic nonce cannot be invalid.
        sealed = try! bytes.withUnsafeBytes { buffer in
            let view = buffer.isEmpty ? Data() : Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: buffer.baseAddress!), count: buffer.count, deallocator: .none)
            return try ChaChaPoly.seal(view, using: temporaryKey)
        }
    }

    /// Encrypt data at the caller's boundary; the source Data is not erased.
    public convenience init(_ data: Data) {
        self.init(SecureBytes(data))
    }

    /// Return fresh zero-on-release plaintext for explicit interoperability.
    /// Prefer `withRevealedBytes` when the use site can remain scoped.
    public func revealedBytes() -> SecureBytes {
        var plaintext = key.withUnsafeBytes { buffer in
            try! ChaChaPoly.open(sealed, using: SymmetricKey(data: buffer))
        }
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        return SecureBytes(plaintext)
    }

    /// Borrow decrypted bytes for `body`; the owned buffer is zeroed on release.
    public func withRevealedBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try revealedBytes().withUnsafeBytes(body)
    }

    public static func == (lhs: ProtectedBytes, rhs: ProtectedBytes) -> Bool {
        if lhs === rhs {
            return true
        }
        return lhs.revealedBytes() == rhs.revealedBytes()
    }
}
