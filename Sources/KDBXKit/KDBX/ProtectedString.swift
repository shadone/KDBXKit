//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A `<String>` element on a KDBX entry — a named field carrying a
    /// (possibly secret) value.
    ///
    /// Used for every text-shaped field on an entry: standard ones
    /// (`Title`, `UserName`, `Password`, `URL`, `Notes`) and any
    /// custom strings the host app or other KDBX clients added. The
    /// `key` is the field name; `value` is a ``Value`` carrying the
    /// payload in a form that respects KDBX's protected-in-memory and
    /// protected-on-disk distinctions.
    ///
    /// ```swift
    /// // Find the entry's Password field.
    /// let pw = entry.strings.first(where: { $0.key == "Password" })?.value
    /// pw?.withRevealedString { plaintext in
    ///     // Use plaintext here; do not retain it.
    /// }
    /// ```
    struct ProtectedString: Sendable, Equatable {
        /// The value of a `<Value>` element inside an entry's `<String>`
        /// node. On-disk protection and resident storage are separate:
        /// regular XML values use zero-on-release SecureBytes; protected values
        /// retain ciphertext, either from the inner stream or ProtectedBytes.
        /// Explicit reveal APIs can produce plaintext copies that callers must
        /// avoid retaining beyond their intended use.
        public enum Value: Sendable {
            /// Plaintext in the XML document.
            case regular(SecureBytes)

            /// Secret encrypted while resident and by the inner stream on save.
            case innerProtected(ProtectedBytes)

            /// Encrypted resident storage for the XML ProtectInMemory hint.
            /// The XML itself remains plaintext, inside the outer vault cipher.
            case memoryProtected(ProtectedBytes)

            /// Inner-cipher ciphertext + the byte offset within the
            /// inner-stream keystream at which the writer wrote it.
            /// Decryption is deferred until a caller actually asks for
            /// the plaintext — so a vault that's been unlocked but
            /// whose passwords haven't been read leaves only ciphertext
            /// in memory. A memory dump captures the inner key (in
            /// `KeystreamSource`) and the ciphertext, but reconstructing
            /// the plaintext still requires the attacker to do the
            /// XOR work — and any plaintext that ever was in memory is
            /// scoped to a `withRevealedString` / `withRevealedBytes`
            /// call frame.
            ///
            /// The reader emits this case for every `Protected="True"`
            /// node; the writer materializes-then-re-encrypts on save
            /// because the inner key regenerates per write anyway
            /// (`KDBXWriter.regenerateSalts: true`).
            case lazyInnerCipher(ciphertext: Data, offset: Int, source: KeystreamSource)

            /// Decrypted plaintext bytes. For `.lazyInnerCipher`, this
            /// runs the inner-cipher decryption on every call and returns
            /// a fresh `SecureBytes` — the returned buffer deinit-zeros
            /// as soon as the caller drops the last reference, so prefer
            /// `withRevealedString` / `withRevealedBytes` over holding
            /// the result.
            public var bytes: SecureBytes {
                switch self {
                case let .regular(b):
                    return b
                case let .innerProtected(b), let .memoryProtected(b):
                    return b.revealedBytes()
                case let .lazyInnerCipher(ciphertext, offset, source):
                    return source.decrypt(ciphertext: ciphertext, at: offset)
                }
            }

            /// Materializes a Swift String for the lifetime of `body`,
            /// then drops the reference so ARC can collect. Use this when
            /// the value needs to cross into UIKit/SwiftUI/clipboard.
            ///
            /// The String is plaintext in process memory while `body`
            /// executes (and briefly after — ARC isn't synchronous). This
            /// is unavoidable at the boundary; the goal is to make the
            /// dwell time millisecond-scale rather than session-scale.
            ///
            /// For `.lazyInnerCipher` values this fires the inner-cipher
            /// decryption inside the call — the decrypted `SecureBytes`
            /// goes out of scope (and zero-deinits) the moment `body`
            /// returns.
            @discardableResult
            public func withRevealedString<R>(_ body: (String) throws -> R) rethrows -> R {
                try bytes.withRevealedString(body)
            }

            /// One-shot materialization. The returned String is plaintext
            /// in the caller's memory and cannot be zeroed — prefer
            /// `withRevealedString` when the caller controls the use site.
            public var revealedString: String {
                bytes.revealedString
            }

            // MARK: - Convenience factories from Strings

            /// Wraps `string`'s UTF-8 bytes in a fresh `SecureBytes`.
            /// The source `String` is still in the caller's heap; this
            /// just shortens the time before the bytes live in a
            /// zero-on-deinit buffer.
            public static func regular(_ string: String) -> Value {
                .regular(SecureBytes(utf8: string))
            }

            @available(*, deprecated, renamed: "innerProtected(_:)")
            public static func unprotected(_ bytes: SecureBytes) -> Value {
                .innerProtected(bytes)
            }

            @available(*, deprecated, renamed: "innerProtected(_:)")
            public static func unprotected(_ string: String) -> Value {
                .innerProtected(string)
            }

            /// Protect a newly entered secret in memory and on XML serialization.
            public static func innerProtected(_ string: String) -> Value {
                .innerProtected(ProtectedBytes(SecureBytes(utf8: string)))
            }

            /// Protect bytes without retaining the caller's plaintext buffer.
            public static func innerProtected(_ bytes: SecureBytes) -> Value {
                .innerProtected(ProtectedBytes(bytes))
            }

            /// Honor the XML-only ProtectInMemory hint with encrypted storage.
            public static func memoryProtected(_ bytes: SecureBytes) -> Value {
                .memoryProtected(ProtectedBytes(bytes))
            }

            /// Protect UTF-8 bytes while preserving the XML-only memory hint.
            public static func memoryProtected(_ string: String) -> Value {
                .memoryProtected(ProtectedBytes(SecureBytes(utf8: string)))
            }

            @available(*, deprecated, renamed: "memoryProtected(_:)")
            public static func protectedInMemory(_ bytes: SecureBytes) -> Value {
                .memoryProtected(bytes)
            }

            @available(*, deprecated, renamed: "memoryProtected(_:)")
            public static func protectedInMemory(_ string: String) -> Value {
                .memoryProtected(string)
            }
        }

        /// The field name (`"Title"`, `"UserName"`, `"Password"`,
        /// `"URL"`, `"Notes"`, or any custom key the host or another
        /// KDBX client added). Standard and custom fields share the
        /// same list on `Entry.strings`.
        public var key: String

        /// The field value. May be a regular protected string, an
        /// memory-only protected one, or a deferred inner-cipher reference;
        /// reveal via ``Value/withRevealedString(_:)``.
        public var value: Value

        public init(key: String, value: Value) {
            self.key = key
            self.value = value
        }
    }
}

extension KDBX.ProtectedString.Value: Equatable {
    /// Two values compare equal when their plaintext byte sequences
    /// match. Lazy values get decrypted on the spot — the cost is one
    /// inner-cipher derivation per side. `SecureBytes.==` is
    /// constant-time across the full byte sequence.
    public static func == (lhs: KDBX.ProtectedString.Value, rhs: KDBX.ProtectedString.Value) -> Bool {
        lhs.bytes == rhs.bytes
    }
}
