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
