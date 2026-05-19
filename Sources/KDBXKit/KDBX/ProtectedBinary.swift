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
            /// Inline binary data carried alongside the entry rather
            /// than via the pool. Present in KDBX 3.1 files (the only
            /// option there) and on any KDBX 4 entry that chose inline
            /// storage rather than a pool reference. The `protected`
            /// flag mirrors the `Protected="True"` attribute on the
            /// `<Value>` element — when set, the bytes are encrypted
            /// with the inner stream cipher in the XML, same as a
            /// protected string.
            case inline(Data, protected: Bool)

            /// Reference into the deduplicated binary pool in
            /// ``InnerHeader/binaryContent`` (KDBX 4) or the
            /// `Meta/Binaries` element (unencrypted XML files).
            /// The protected status for a referenced binary lives on
            /// the pool entry's `shouldBeProtected` flag, not here —
            /// refs are pointers, not data.
            case ref(UInt32)
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
