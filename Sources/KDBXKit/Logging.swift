//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Logging

/// Loggers for KDBXKit's internal subsystems. Uses swift-log so the
/// library is portable across Apple platforms and Linux. The host
/// application is responsible for installing a `LogHandler` (e.g.
/// route to unified logging on Apple via an os.Logger-backed handler,
/// or `StreamLogHandler.standardOutput` on Linux/server). Library code
/// shouldn't bootstrap the logging system itself; we just emit through
/// `Logger`.
///
/// All internal diagnostics route through these loggers at `.debug`
/// level so they're invisible under default backend filtering but
/// available when a host opts in.
enum KDBXLog {
    private static let subsystem = "info.ddenis.KDBXKit"

    /// XML parser warnings about unexpected / unknown elements. Most KDBX
    /// files don't trigger these; when they do, the file usually still
    /// parses correctly — the unknown element is just skipped.
    static let parser = Logger(label: "\(subsystem).parser")

    /// Header-reader warnings: unknown field types, unexpected variant
    /// dictionary entries.
    static let header = Logger(label: "\(subsystem).header")

    /// Inner-header reader warnings.
    static let innerHeader = Logger(label: "\(subsystem).innerHeader")

    /// KDF parameter validation warnings (missing required fields,
    /// unsupported Argon2 version, etc.).
    static let kdf = Logger(label: "\(subsystem).kdf")
}
