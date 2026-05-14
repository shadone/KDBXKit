//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    struct ProtectedString: Sendable, Equatable {
        /// The value of a `<Value>` element inside an entry's `<String>`
        /// node. Three forms exist in the KDBX spec; all of them carry
        /// secret-shaped bytes from our perspective (passwords, TOTP seeds,
        /// notes), so the payload is always `SecureBytes` — a page-locked,
        /// zero-on-deinit wrapper — rather than a `Swift.String` which
        /// can't be securely zeroed and would persist on the heap until
        /// ARC collects it.
        public enum Value: Sendable, Equatable {
            /// Plaintext in the XML document.
            case regular(SecureBytes)

            /// Was stored encrypted with the inner stream cipher in the XML
            /// document; here it's the **decrypted** bytes. (The case name
            /// reflects its in-memory state, not the on-disk state.)
            case unprotected(SecureBytes)

            /// Used only in unencrypted XML files (very rare in practice).
            case protectedInMemory(SecureBytes)

            /// Direct read access to the underlying bytes. Use this
            /// when handing the value to crypto APIs or comparing.
            public var bytes: SecureBytes {
                switch self {
                case let .regular(b), let .unprotected(b), let .protectedInMemory(b):
                    return b
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
            public static func unprotected(_ string: String) -> Value {
                .unprotected(SecureBytes(utf8: string))
            }
            public static func protectedInMemory(_ string: String) -> Value {
                .protectedInMemory(SecureBytes(utf8: string))
            }
        }

        public var key: String
        public var value: Value

        public init(key: String, value: Value) {
            self.key = key
            self.value = value
        }
    }
}
