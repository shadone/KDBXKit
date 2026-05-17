//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Authentic interop test against the actual KeePassXC binary. Each test
/// is gated on the CLI's presence so CI without KeePassXC installed
/// silently no-ops, while a local dev run gets a hard regression net.
///
/// Caught (in the session this was added in): the writer emitting
/// `<?xml encoding=…>` without the mandatory `version="1.0"` attribute.
/// Every internal round-trip happily passed because our reader is
/// lenient; KeePassXC's stricter parser bailed with "No root group".
@Suite("KeePassXC interop — round-trip via the real binary")
struct KeePassXCInteropTests {
    static let cliPath = "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"
    static var cliAvailable: Bool { FileManager.default.isExecutableFile(atPath: cliPath) }

    @Test(
        "Our writer's output is readable by keepassxc-cli ls",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourOutput_readableByKeePassXC() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-rich", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "123")

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: unlock)

        let tempDir = FileManager.default.temporaryDirectory
        let outPath = tempDir.appendingPathComponent("kdbxkit-interop-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }

        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        let output = try runCLI(["ls", "-R", outPath], stdin: "123\n")
        // Every top-level title from the fixture should be visible.
        #expect(output.contains("GitHub"))
        #expect(output.contains("Unicode 测试 🌍"))
        #expect(output.contains("Work/"))
        #expect(output.contains("Servers/"))
        #expect(output.contains("Prod"))
    }

    @Test(
        "Protected fields written by us decrypt correctly under keepassxc-cli show",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourOutput_protectedFieldsDecryptUnderKeePassXC() throws {
        let path = Bundle.module.path(forResource: "Resources/kpxc-rich", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "123")

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: unlock)

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-interop-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }

        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        // -s shows secrets (including the protected Password).
        let output = try runCLI(["show", "-s", outPath, "Unicode 测试 🌍"], stdin: "123\n")
        #expect(output.contains("Title: Unicode 测试 🌍"))
        #expect(output.contains("UserName: 用户"))
        #expect(output.contains("Password: ünïcödé-päss-🔐"))
        #expect(output.contains("汉字"))
    }

    @Test(
        "Round-trip through KeePassXC preserves comma-tags written as semicolon-tags",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourOutput_preservesTagsAcrossDialects() throws {
        // kpxc-extras carries `2fa,login,work` (KeePassXC's comma dialect).
        // Our reader splits on either separator; our writer emits `;`.
        // The real test: KeePassXC must still find the entry (and round-trip
        // the tag attribute as it likes) when we hand back `;`-separated.
        let path = Bundle.module.path(forResource: "Resources/kpxc-extras", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "test")

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: unlock)

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-interop-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }

        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        let output = try runCLI(["show", outPath, "GitHub"], stdin: "test\n")
        // KeePassXC's `show` prints the tags line. Our writer emits them
        // semicolon-separated; KeePassXC accepts either form.
        #expect(output.contains("Tags:"))
        #expect(output.contains("2fa"))
        #expect(output.contains("login"))
        #expect(output.contains("work"))
        // Custom string fields also survive the full round-trip.
        #expect(output.contains("Title: GitHub"))
    }

    @Test(
        "Our writer's keyfile-protected output is readable by keepassxc-cli",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourKeyfileOutput_readableByKeePassXC() throws {
        // Take the bundled kpxc-keyfile.kdbx + .key (which keepassxc-cli
        // itself generated), read it with our reader, write it back with
        // our writer using the same credentials, and hand the result back
        // to keepassxc-cli. Catches keyfile-related encoding regressions
        // end-to-end through both directions.
        let dbPath = Bundle.module.path(forResource: "Resources/kpxc-keyfile", ofType: "kdbx")!
        let kfPath = Bundle.module.path(forResource: "Resources/kpxc-keyfile", ofType: "key")!
        let data = try Data(contentsOf: URL(filePath: dbPath))
        let keyFile = try Data(contentsOf: URL(filePath: kfPath))
        let unlock = UnlockData(masterPassword: "123", keyFile: keyFile)

        var reader = KDBXReader(data)
        let content = try reader.parse(unlockData: unlock)

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-interop-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }

        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        let output = try runCLI(["ls", "-k", kfPath, outPath], stdin: "123\n")
        // Just need a non-error response from KeePassXC on a keyfile +
        // password unlock of our output.
        #expect(!output.contains("Error"))
        #expect(!output.contains("Invalid credentials"))
    }

    @Test(
        "Meta.customData with our `passie:` keys survives a round-trip through keepassxc-cli",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func customData_survivesKeePassXCRoundTrip() throws {
        // Write a vault carrying a synthetic passie:vaultID, then have
        // keepassxc-cli mutate it (add an entry — forces a re-encrypt
        // through KeePassXC's writer), then reopen with KDBXKit and
        // assert the customData entry survived. KDBX 4.1 spec says
        // unknown CustomData round-trips; this test pins KeePassXC to
        // that promise so a future version that silently drops unknown
        // keys would surface as a build failure here.
        let unlock = UnlockData(masterPassword: "interop")
        var content = KDBXContent.makeEmpty(databaseName: "Interop", kdf: .fast)
        let vaultID = UUID().uuidString
        let now = Date()
        content.database.meta.customData.append(.init(
            key: "passie:vaultID",
            value: vaultID,
            lastModificationTime: now
        ))

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-customdata-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }
        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        // Force KeePassXC to write the file. `add` is the smallest
        // re-encrypting mutation we can drive non-interactively.
        // Password prompt is read twice on add: master + new-entry.
        let addOut = try runCLI(
            ["add", "-p", outPath, "/InteropProbe"],
            stdin: "interop\nentry-pw\n"
        )
        // Sanity — the add succeeded; bail loudly if it didn't so the
        // next assertion isn't measuring the wrong thing.
        #expect(!addOut.contains("Error"), "keepassxc-cli add failed: \(addOut)")

        // Reopen via KDBXKit. The customData entry should still be there.
        let data = try Data(contentsOf: URL(filePath: outPath))
        let roundTripped = try KDBXReader.parse(data, unlockData: unlock)
        let preserved = roundTripped.database.meta.customData.first {
            $0.key == "passie:vaultID"
        }
        #expect(preserved?.value == vaultID, "passie:vaultID was dropped by keepassxc-cli round-trip")
    }

    private func runCLI(_ args: [String], stdin: String) throws -> String {
        let process = Process()
        process.executableURL = URL(filePath: Self.cliPath)
        process.arguments = args

        let stdoutPipe = Pipe()
        let stdinPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stdoutPipe
        process.standardInput = stdinPipe

        try process.run()
        try stdinPipe.fileHandleForWriting.write(contentsOf: Data(stdin.utf8))
        try stdinPipe.fileHandleForWriting.close()

        let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
