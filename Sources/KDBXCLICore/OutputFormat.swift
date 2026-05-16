//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation

enum OutputFormat: String, ExpressibleByArgument, CaseIterable {
    case human
    case json
}

struct OutputOptions: ParsableArguments {
    @Option(
        name: [.customShort("o"), .customLong("output")],
        help: ArgumentHelp(
            "Output format. `human` is line-oriented and meant for terminals; `json` emits a single JSON document on stdout for piping into `jq`.",
            valueName: "human|json"
        )
    )
    var format: OutputFormat = .human
}

/// Shared encoder for JSON output. Sorted keys + pretty printing so diffs and
/// `jq`-style use both stay readable. Dates are emitted as ISO-8601 strings.
let jsonOutputEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}()

/// Encode a payload to JSON and print to stdout with a trailing newline.
func printJSON(_ value: some Encodable) throws {
    let data = try jsonOutputEncoder.encode(value)
    if let str = String(data: data, encoding: .utf8) {
        print(str)
    }
}
