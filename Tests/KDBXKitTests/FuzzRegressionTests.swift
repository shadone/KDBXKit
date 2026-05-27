//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Replays libFuzzer crashers checked into `Fuzz/crashers/<target>/`. Each file
/// is a byte blob that once crashed a parser; feeding it back must now produce a
/// typed error or a clean result — never a trap. Runs in normal `swift test`, so
/// a crasher that was found and fixed never silently regresses.
///
/// While `Fuzz/crashers/<target>/` holds only `.gitkeep`, these tests are
/// no-ops that prove the loader wiring. Each fixed crasher added there becomes a
/// permanent regression case automatically.
@Suite("Fuzz regression — checked-in crashers stay fixed")
struct FuzzRegressionTests {
    /// Walk from this source file up to the repo root, then into Fuzz/crashers.
    private static func crasherFiles(target: String) -> [URL] {
        let here = URL(fileURLWithPath: #filePath)
        let repoRoot = here
            .deletingLastPathComponent() // KDBXKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root
        let dir = repoRoot.appendingPathComponent("Fuzz/crashers/\(target)")
        let contents = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return contents.filter { $0.lastPathComponent != ".gitkeep" }
    }

    private func data(of url: URL) throws -> Data { try Data(contentsOf: url) }

    @Test
    func headerCrashersAreHandled() throws {
        for url in Self.crasherFiles(target: "header") {
            _ = try? KDBXReader.parseHeader(try data(of: url))
        }
    }

    @Test
    func parseCrashersAreHandled() throws {
        let unlock = UnlockData(masterPassword: "fuzz")
        let tiny = KDFParameterLimits(maxArgon2Memory: 1 << 20, maxArgon2Iterations: 2, maxArgon2Parallelism: 2, maxAESKDFRounds: 10000)
        for url in Self.crasherFiles(target: "parse") {
            _ = try? KDBXReader.parse(try data(of: url), unlockData: unlock, kdfLimits: tiny)
        }
    }

    @Test
    func variantDictCrashersAreHandled() throws {
        for url in Self.crasherFiles(target: "variantdict") {
            let reader = VariantDictionaryReader(data: try data(of: url))
            _ = try? reader.parse()
        }
    }

    @Test
    func blockStreamCrashersAreHandled() throws {
        for url in Self.crasherFiles(target: "blockstream") {
            _ = try? HashedBlockStreamReader.decode(try data(of: url))
        }
    }

    @Test
    func xmlCrashersAreHandled() throws {
        let keystream = KeystreamSource(algorithm: .chacha20, key: SecureBytes(Data(repeating: 0, count: 32)), nonce: Data(repeating: 0, count: 12))
        for url in Self.crasherFiles(target: "xml") {
            guard let xml = String(data: try data(of: url), encoding: .utf8) else { continue }
            let reader = try? XMLDocumentReader(xmlDocument: xml, keystreamSource: keystream)
            _ = try? reader?.parse()
        }
    }
}
