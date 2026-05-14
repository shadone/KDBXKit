//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import os

/// Loggers for KDBXKit's internal subsystems. Use `os.Logger` so log output
/// goes through unified logging on Apple platforms (visible in Console.app,
/// can be filtered by subsystem / category, never written to stdout).
///
/// A library shouldn't `print()` — that pollutes stdout for every host app.
/// All previous `print()` calls in KDBXKit now route through these loggers
/// at `.debug` level so they're invisible by default but available for
/// diagnostic captures via `log show` / Console.app filtering.
enum KDBXLog {
    private static let subsystem = "info.ddenis.KDBXKit"

    /// XML parser warnings about unexpected / unknown elements. Most KDBX
    /// files don't trigger these; when they do, the file usually still
    /// parses correctly — the unknown element is just skipped.
    static let parser = Logger(subsystem: subsystem, category: "parser")

    /// Header-reader warnings: unknown field types, unexpected variant
    /// dictionary entries.
    static let header = Logger(subsystem: subsystem, category: "header")

    /// Inner-header reader warnings.
    static let innerHeader = Logger(subsystem: subsystem, category: "innerHeader")

    /// KDF parameter validation warnings (missing required fields,
    /// unsupported Argon2 version, etc.).
    static let kdf = Logger(subsystem: subsystem, category: "kdf")
}
