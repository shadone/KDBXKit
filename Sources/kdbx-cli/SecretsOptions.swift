//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser

/// Controls whether protected fields (e.g. `Password`) appear in cleartext or
/// are masked. Default-masked: a debug tool prints to a terminal that might be
/// shared on a screen or piped to logs.
struct SecretsOptions: ParsableArguments {
    @Flag(
        name: .customLong("show-secrets"),
        help: "Reveal protected fields in cleartext. Off by default — protected fields print as `***`."
    )
    var showSecrets: Bool = false
}

/// Placeholder rendered in human and JSON output when a protected field is
/// masked. Fixed-length on purpose — no length leakage.
let maskedFieldPlaceholder = "***"
