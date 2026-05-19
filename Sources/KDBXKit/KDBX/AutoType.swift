//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX {
    /// Auto-type configuration on a KDBX entry — the keystroke
    /// sequence and per-window-title associations the KeePass UI uses
    /// to type credentials into other apps.
    ///
    /// Auto-type is a desktop-KeePass feature (Windows / macOS /
    /// Linux). Mobile clients and headless tooling typically don't
    /// invoke it; for those hosts the field is metadata that round-
    /// trips on save without otherwise affecting behavior.
    ///
    /// See <https://keepass.info/help/base/autotype.html>.
    struct AutoType: Sendable, Equatable {
        /// Whether auto-type is enabled for this entry. `nil` means
        /// "inherit from the parent group" (see
        /// ``Group/enableAutoType``). `false` disables auto-type for
        /// this entry even if the group permits it.
        public var enabled: Bool?

        /// Obfuscation strategy for auto-type — how the keystroke
        /// sequence is sent to defeat naive keyloggers.
        public enum DataTransferObfuscation: Int32, Sendable, Equatable {
            /// Plain keystrokes. No obfuscation.
            case noObfuscation = 0

            /// "Two-channel" obfuscation: mix clipboard + keystrokes
            /// so a keylogger alone can't reconstruct the full
            /// secret. Detail at
            /// <https://keepass.info/help/v2/autotype_obfuscation.html>.
            case twoChannelObfuscation = 1
        }

        /// The chosen obfuscation strategy. `nil` falls back to
        /// `noObfuscation` in clients that honor auto-type.
        public var dataTransferObfuscation: DataTransferObfuscation?

        /// Default keystroke sequence used when no per-window
        /// association in ``association`` matches the target window.
        /// `nil` means inherit the group default
        /// (``Group/defaultAutoTypeSequence``) and ultimately the
        /// vault default.
        public var defaultSequence: String?

        /// A per-window-title override mapping.
        ///
        /// When the user triggers auto-type, the KeePass UI walks the
        /// associations on the matched entry and uses the first
        /// `keystrokeSequence` whose `window` pattern matches the
        /// currently-active window title.
        public struct Association: Sendable, Equatable {
            /// Window-title pattern. Plain substring match in the
            /// simple case; supports wildcards (`*`) and regex (the
            /// `//.../` syntax) in KeePass's auto-type matcher.
            public var window: String

            /// Keystroke sequence to send when this association
            /// matches — same syntax as ``AutoType/defaultSequence``.
            public var keystrokeSequence: String
        }

        /// Per-window-title overrides, evaluated in order. When none
        /// match, ``defaultSequence`` (or the inherited default) is
        /// used.
        public var association: [Association]

        public init(
            enabled: Bool? = nil,
            dataTransferObfuscation: DataTransferObfuscation? = nil,
            defaultSequence: String? = nil,
            association: [Association] = []
        ) {
            self.enabled = enabled
            self.dataTransferObfuscation = dataTransferObfuscation
            self.defaultSequence = defaultSequence
            self.association = association
        }
    }
}
