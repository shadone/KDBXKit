//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// A source-level gate: the byte-level parsing trees must not introduce
/// process-trapping primitives. A `fatalError` / `try!` / `as!` reached on a
/// malformed-input path turns a recoverable parse error into a crash (and on
/// the iOS AutoFill extension, a jetsam-style kill). The migration to
/// `ByteCursor` removed the hand-rolled bounds checks that used to motivate
/// these; this test stops new ones from creeping back in.
///
/// Known-safe exceptions are allowlisted by exact source line (see
/// `allowedTrapLines`): the inner-stream cipher constructors run on
/// length-validated key/nonce material, and one writer-side `fatalError`
/// guards a programmer-error invariant already enforced upstream at the
/// parse->write boundary.
@Suite("No trap primitives in parser trees")
struct NoTrapPrimitivesGateTests {
    /// Directories under `Sources/KDBXKit` whose code runs on attacker-
    /// controlled bytes and therefore must stay trap-free.
    private static let scannedDirectories = ["Header", "InnerHeader", "Database", "XML"]

    /// Patterns that turn bad input into a process trap.
    private static let bannedPatterns = [
        "preconditionFailure(",
        "assertionFailure(",
        "fatalError(",
        "try!",
        "as!",
    ]

    /// Exact (trimmed) source lines permitted to contain a banned pattern,
    /// each justified. Keyed by file basename so a line can't be smuggled in
    /// by moving it to another file.
    private static let allowedTrapLines: Set<String> = [
        // Inner-stream cipher constructors: the key and nonce lengths are
        // validated before these run, so the throwing initializer cannot
        // actually fail. (KeystreamSource / InnerHeader+cryptor.)
        "InnerHeader+cryptor.swift|return try! ChaCha20(key: key, iv: nonce)",
        "InnerHeader+cryptor.swift|return try! Salsa20(key: key, iv: nonce)",
        "KeystreamSource.swift|return try! ChaCha20(key: keyData, iv: nonce, blockCounter: UInt32(truncatingIfNeeded: blockCounter))",
        "KeystreamSource.swift|return try! Salsa20(key: keyData, iv: nonce, blockCounter: blockCounter)",
        // Writer-only programmer-error guard: a `.unknown` KDF reaching the
        // serializer means an upstream save-time check (which rejects
        // unsupported KDFs) was bypassed. Not an adversarial-input path.
        "KDFParameters.swift|fatalError(\"Writing unsupported KDF Parameters is not implemented: \\(uuid.uuidString)\")",
    ]

    /// Locate the repository's `Sources/KDBXKit` directory from this test
    /// file's location (Tests/KDBXKitTests/...), independent of CWD.
    private func sourcesRoot() -> URL {
        URL(filePath: #filePath) // .../Tests/KDBXKitTests/NoTrapPrimitivesGateTests.swift
            .deletingLastPathComponent() // KDBXKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root
            .appending(path: "Sources/KDBXKit")
    }

    /// Strip a trailing `//` line comment so a banned token mentioned in prose
    /// (e.g. "toVariantDictionary() has a fatalError") isn't flagged. Good
    /// enough for this tree: no `//` appears inside string literals here.
    private func codePortion(of line: String) -> String {
        guard let range = line.range(of: "//") else { return line }
        return String(line[..<range.lowerBound])
    }

    @Test("No new fatalError / try! / as! in Header, InnerHeader, Database, XML")
    func parserTreesAreTrapFree() throws {
        let root = sourcesRoot()
        var violations: [String] = []

        for dir in Self.scannedDirectories {
            let dirURL = root.appending(path: dir)
            let enumerator = FileManager.default.enumerator(at: dirURL, includingPropertiesForKeys: nil)
            while let url = enumerator?.nextObject() as? URL {
                guard url.pathExtension == "swift" else { continue }
                let basename = url.lastPathComponent
                let contents = try String(contentsOf: url, encoding: .utf8)
                for rawLine in contents.split(separator: "\n", omittingEmptySubsequences: false) {
                    let code = codePortion(of: String(rawLine))
                    guard Self.bannedPatterns.contains(where: { code.contains($0) }) else { continue }
                    let key = "\(basename)|\(code.trimmingCharacters(in: .whitespaces))"
                    if !Self.allowedTrapLines.contains(key) {
                        violations.append(key)
                    }
                }
            }
        }

        #expect(
            violations.isEmpty,
            """
            Trap primitive found on a parsing path. Replace it with a typed throw,
            or — if genuinely unreachable on malformed input — add the exact line to
            allowedTrapLines with a justification. Offending lines:
            \(violations.joined(separator: "\n"))
            """
        )
    }

    @Test("The allowlist has no stale entries")
    func allowlistIsNotStale() throws {
        // A justified-trap line that no longer exists means the allowlist is
        // drifting; prune it so the gate stays honest.
        let root = sourcesRoot()
        var present: Set<String> = []
        for dir in Self.scannedDirectories {
            let dirURL = root.appending(path: dir)
            let enumerator = FileManager.default.enumerator(at: dirURL, includingPropertiesForKeys: nil)
            while let url = enumerator?.nextObject() as? URL {
                guard url.pathExtension == "swift" else { continue }
                let basename = url.lastPathComponent
                let contents = try String(contentsOf: url, encoding: .utf8)
                for rawLine in contents.split(separator: "\n", omittingEmptySubsequences: false) {
                    let code = codePortion(of: String(rawLine))
                    guard Self.bannedPatterns.contains(where: { code.contains($0) }) else { continue }
                    present.insert("\(basename)|\(code.trimmingCharacters(in: .whitespaces))")
                }
            }
        }
        let stale = Self.allowedTrapLines.subtracting(present)
        #expect(stale.isEmpty, "Stale allowlist entries (no longer in source): \(stale.sorted())")
    }
}
