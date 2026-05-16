//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

extension DB {
    struct Validate: ParsableCommand {
        enum Level: String, ExpressibleByArgument, CaseIterable {
            case error
            case warning
        }

        static let configuration = CommandConfiguration(
            commandName: "validate",
            abstract: "Validate a vault's content and exit non-zero if findings exist at or above --level."
        )

        @OptionGroup()
        var commonOptions: CommonOptions

        @OptionGroup()
        var outputOptions: OutputOptions

        @Option(
            name: .customLong("level"),
            help: ArgumentHelp(
                "Minimum severity that causes a non-zero exit. `error` (default) fails only on errors; `warning` also fails on warnings.",
                valueName: "error|warning"
            )
        )
        var level: Level = .error

        mutating func run() throws {
            let unlockData = try commonOptions.credentials.resolve(requireUnlock: true)
            guard
                case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: unlockData)
            else {
                throw AppError.wrongCredentials
            }

            let issues = content.validate()
            let snapshot = ValidationSnapshot(issues: issues)

            switch outputOptions.format {
            case .human:
                snapshot.printHuman()
            case .json:
                try printJSON(snapshot)
            }

            if snapshot.shouldFail(at: level) {
                throw ExitCode.failure
            }
        }
    }
}

struct ValidationSnapshot: Encodable {
    struct Issue: Encodable {
        let level: String
        let message: String
    }

    let issues: [Issue]
    let counts: Counts

    struct Counts: Encodable {
        let error: Int
        let warning: Int
        let total: Int
    }

    init(issues raw: [ValidationFailure]) {
        let mapped = raw.map { Issue(level: "\($0.level)".lowercased(), message: $0.message) }
        issues = mapped
        let errorCount = raw.filter { if case .error = $0.level { return true } else { return false } }.count
        let warningCount = raw.count - errorCount
        counts = Counts(error: errorCount, warning: warningCount, total: raw.count)
    }

    func printHuman() {
        if issues.isEmpty {
            print("OK — no validation issues.")
            return
        }
        for issue in issues {
            print("\(issue.level): \(issue.message)")
        }
        print("")
        print("Summary: \(counts.error) error(s), \(counts.warning) warning(s).")
    }

    func shouldFail(at threshold: DB.Validate.Level) -> Bool {
        switch threshold {
        case .error:
            return counts.error > 0
        case .warning:
            return counts.total > 0
        }
    }
}
