//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// A binary attachment on an entry — a file (image, document,
    /// keyfile copy, etc.) stored inside the vault.
    ///
    /// The ``key`` is the attachment's filename as the user sees it;
    /// the ``value`` carries either inline bytes or a reference into
    /// the vault's binary pool.
    ///
    /// KDBX 4.x stores binary payloads in a deduplicated pool inside
    /// ``InnerHeader``, and entries reference pool slots by index —
    /// two byte-identical attachments on different entries cost one
    /// pool entry. KDBX 3.1 stores binaries inline in the XML; KDBXKit
    /// reads either form and migrates 3.1 inline binaries into a 4.x
    /// pool on save.
    struct ProtectedBinary: Sendable, Equatable {
        /// The on-disk shape of an attachment's payload.
        public enum Value: Sendable, Equatable {
            /// Plain inline bytes, without requested memory protection.
            case plainInline(Data)

            /// Protected inline bytes stay encrypted until explicitly revealed.
            case protectedInline(ProtectedBytes)

            /// Compatibility constructor. Protected values now encrypt their
            /// resident storage. Pattern matching uses plainInline/protectedInline.
            @available(*, deprecated, renamed: "makeInline(_:protected:)")
            public static func inline(_ data: Data, protected: Bool) -> Value {
                makeInline(data, protected: protected)
            }

            /// Construct an inline payload that honors its memory-protection flag.
            /// Prefer this factory when the protection flag is chosen at runtime.
            public static func makeInline(_ data: Data, protected: Bool) -> Value {
                protected ? .protectedInline(ProtectedBytes(data)) : .plainInline(data)
            }

            /// Construct an inline payload from an owned secure buffer.
            public static func makeInline(_ bytes: SecureBytes, protected: Bool) -> Value {
                protected ? .protectedInline(ProtectedBytes(bytes)) : .plainInline(bytes.toData())
            }

            /// Explicit plaintext copy of an inline payload, or nil for a ref.
            public var inlineData: Data? {
                switch self {
                case let .plainInline(data): return data
                case let .protectedInline(bytes): return bytes.withRevealedBytes { Data($0) }
                case .ref: return nil
                }
            }

            /// Inline byte count without decrypting, or nil for a pool reference.
            public var inlineByteCount: Int? {
                switch self {
                case let .plainInline(data): return data.count
                case let .protectedInline(bytes): return bytes.count
                case .ref: return nil
                }
            }

            /// Whether the inline payload requests memory protection.
            public var isProtected: Bool {
                switch self {
                case .plainInline: return false
                case .protectedInline: return true
                case .ref: return false
                }
            }

            /// Reference into the deduplicated binary pool in
            /// ``InnerHeader/binaryContent`` (KDBX 4) or the
            /// `Meta/Binaries` element (unencrypted XML files).
            /// The protected status for a referenced binary lives on
            /// the pool entry's `shouldBeProtected` flag, not here —
            /// refs are pointers, not data.
            case ref(UInt32)

            public static func == (lhs: Value, rhs: Value) -> Bool {
                switch (lhs, rhs) {
                case let (.ref(a), .ref(b)): return a == b
                case let (.plainInline(a), .plainInline(b)): return a == b
                case let (.protectedInline(a), .protectedInline(b)): return a == b
                default: return false
                }
            }
        }

        /// The attachment's filename as the user sees it. Not unique
        /// across the vault — two entries can each have an attachment
        /// named `"id.png"`.
        public let key: String

        /// The attachment payload. See ``Value`` for inline vs pool-ref
        /// storage.
        public let value: Value

        public init(key: String, value: Value) {
            self.key = key
            self.value = value
        }
    }
}
