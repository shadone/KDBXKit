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

    /// Enforcement hook for "the interop net actually ran". Every other test
    /// is gated on `cliAvailable`, so on a runner without KeePassXC the whole
    /// suite skips and a green run hides zero real interop coverage. A CI lane
    /// that is supposed to have KeePassXC sets `KDBXKIT_REQUIRE_INTEROP=1`;
    /// this test then fails loudly if the CLI is missing instead of skipping.
    /// Locally (variable unset) it is a no-op, so dev runs aren't blocked.
    @Test("Interop net is present when required (KDBXKIT_REQUIRE_INTEROP)")
    func interopNetRequiredWhenAsked() {
        guard ProcessInfo.processInfo.environment["KDBXKIT_REQUIRE_INTEROP"] == "1" else { return }
        #expect(
            Self.cliAvailable,
            "KDBXKIT_REQUIRE_INTEROP=1 but keepassxc-cli is missing at \(Self.cliPath) — the interop suite would silently no-op. Install KeePassXC or unset the variable."
        )
    }

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
        "Round-trip through KeePassXC preserves comma-separated tags",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourOutput_preservesTagsAcrossDialects() throws {
        // kpxc-extras carries `2fa,login,work` (KeePassXC's comma dialect).
        // Our reader splits on either `;` or `,`; our writer emits `,` to
        // match KeePassXC's preferred form. The real test: KeePassXC must
        // still find the entry and round-trip the tag attribute.
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
        // comma-separated (matching KeePassXC); KeePassXC accepts either form.
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
        let unlock = try UnlockData(masterPassword: "123", keyFile: keyFile)

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
        var content = KDBXContent.makeEmpty(databaseName: "Interop")
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

    @Test(
        "Attachments written by us export byte-perfect via keepassxc-cli attachment-export",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourAttachments_exportableByKeePassXC() throws {
        // Build a fresh vault carrying a pool of attachments with sizes
        // chosen to exercise both the small-payload path and the
        // multi-chunk gzip path through KDBXWriter's streaming pipeline.
        // Only a real KeePassXC decode proves the gzip framing is
        // correct (header, DEFLATE body, CRC32+ISIZE trailer).
        let unlock = UnlockData(masterPassword: "interop")
        var content = KDBXContent.makeEmpty(databaseName: "AttachInterop")

        let payloads: [(name: String, data: Data, protected: Bool)] = [
            ("tiny.txt", Data("hi".utf8), false),
            ("hello.txt", Data("hello, world — KDBXKit ↔ KeePassXC interop 🔁".utf8), false),
            ("random-4k.bin", randomBytes(count: 4096), false),
            ("random-64k.bin", randomBytes(count: 64 * 1024), false),
            ("secret.bin", Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x13]), true),
        ]

        let now = Date()
        var entry = KDBX.Entry(uuid: UUID(), times: .init(creationTime: now, lastModificationTime: now))
        entry.strings = [
            .init(key: "Title", value: .regular("Files")),
            .init(key: "UserName", value: .regular("")),
            .init(key: "Password", value: .regular("")),
            .init(key: "URL", value: .regular("")),
            .init(key: "Notes", value: .regular("")),
        ]
        for (i, payload) in payloads.enumerated() {
            content.innerHeader.binaryContent.append(
                .init(shouldBeProtected: payload.protected, data: payload.data)
            )
            entry.binaries.append(
                .init(key: payload.name, value: .ref(UInt32(i)))
            )
        }
        content.database.root.group.entries.append(entry)

        let tmp = FileManager.default.temporaryDirectory
        let dbPath = tmp.appendingPathComponent("kdbxkit-attach-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let outputStream = OutputStream(toFileAtPath: dbPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        // Sanity: keepassxc-cli can list the entry at all.
        let ls = try runCLI(["ls", dbPath], stdin: "interop\n")
        #expect(ls.contains("Files"), "keepassxc-cli could not see /Files: \(ls)")

        // Export each attachment to a file and compare bytes.
        for payload in payloads {
            let exportPath = tmp.appendingPathComponent("export-\(UUID().uuidString).bin").path
            defer { try? FileManager.default.removeItem(atPath: exportPath) }

            let out = try runCLI(
                ["attachment-export", dbPath, "Files", payload.name, exportPath],
                stdin: "interop\n"
            )
            #expect(!out.contains("ERROR"), "attachment-export failed for \(payload.name): \(out)")

            let exported = try Data(contentsOf: URL(filePath: exportPath))
            #expect(
                exported == payload.data,
                "attachment \(payload.name) round-trip via KeePassXC differs (orig \(payload.data.count)B, exported \(exported.count)B)"
            )
        }
    }

    @Test(
        "Attachments written by us survive a keepassxc-cli re-encrypt and re-read intact",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func ourAttachments_surviveKeePassXCRoundTrip() throws {
        // Write a vault with several attachments, force keepassxc-cli
        // to load + re-save it (attachment-import is the smallest
        // non-interactive mutation that re-encrypts the whole file),
        // then re-open with KDBXKit and assert every original
        // attachment's bytes survived. Catches anything KeePassXC
        // would silently rewrite differently — DEFLATE framing, inner
        // header binary flags, pool index ordering.
        let unlock = UnlockData(masterPassword: "rt")
        var content = KDBXContent.makeEmpty(databaseName: "AttachRT")

        let originals: [(name: String, data: Data, protected: Bool)] = [
            ("notes.txt", Data("first line\nsecond line — with é and 漢\n".utf8), false),
            ("blob-1k.bin", randomBytes(count: 1024), false),
            ("blob-16k.bin", randomBytes(count: 16 * 1024), true),
        ]

        let now = Date()
        var entry = KDBX.Entry(uuid: UUID(), times: .init(creationTime: now, lastModificationTime: now))
        entry.strings = [
            .init(key: "Title", value: .regular("Probe")),
            .init(key: "UserName", value: .regular("")),
            .init(key: "Password", value: .regular("")),
            .init(key: "URL", value: .regular("")),
            .init(key: "Notes", value: .regular("")),
        ]
        for (i, payload) in originals.enumerated() {
            content.innerHeader.binaryContent.append(
                .init(shouldBeProtected: payload.protected, data: payload.data)
            )
            entry.binaries.append(
                .init(key: payload.name, value: .ref(UInt32(i)))
            )
        }
        content.database.root.group.entries.append(entry)

        let tmp = FileManager.default.temporaryDirectory
        let dbPath = tmp.appendingPathComponent("kdbxkit-attach-rt-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let outputStream = OutputStream(toFileAtPath: dbPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        // Force a full re-encrypt by importing one more attachment via
        // keepassxc-cli. The CLI rewrites the entire file, which is
        // the path that matters for interop — any divergence in our
        // output that KeePassXC's reader is lenient about (but
        // mangles on rewrite) shows up here.
        let injectedData = randomBytes(count: 2048)
        let injectedName = "injected.bin"
        let injectedPath = tmp.appendingPathComponent("inject-\(UUID().uuidString).bin").path
        defer { try? FileManager.default.removeItem(atPath: injectedPath) }
        try injectedData.write(to: URL(filePath: injectedPath))

        let importOut = try runCLI(
            ["attachment-import", dbPath, "Probe", injectedName, injectedPath],
            stdin: "rt\n"
        )
        #expect(!importOut.contains("ERROR"), "keepassxc-cli attachment-import failed: \(importOut)")

        // Re-open with KDBXKit. Each original attachment must still
        // resolve to the same bytes via the entry's ref index, and
        // the injected one must show up too.
        let reread = try KDBXReader.parse(
            try Data(contentsOf: URL(filePath: dbPath)),
            unlockData: unlock
        )
        let probe = reread.database.root.group.entries.first { entry in
            entry.strings.first { $0.key == "Title" }?.value.bytes.withRevealedString { $0 } == "Probe"
        }
        try #require(probe != nil, "Probe entry vanished after keepassxc-cli re-save")

        for payload in originals {
            let binary = probe?.binaries.first { $0.key == payload.name }
            try #require(binary != nil, "binary \(payload.name) missing after round-trip")
            guard case let .ref(idx) = binary?.value else {
                Issue.record("binary \(payload.name) was not stored as a ref after KeePassXC re-save")
                continue
            }
            try #require(
                Int(idx) < reread.innerHeader.binaryContent.count,
                "binary \(payload.name) ref index \(idx) out of bounds"
            )
            let pooled = reread.innerHeader.binaryContent[Int(idx)]
            #expect(
                pooled.data == payload.data,
                "attachment \(payload.name) bytes diverged after KeePassXC re-save"
            )
        }

        // The newly-injected attachment is also present and matches.
        let injectedBinary = probe?.binaries.first { $0.key == injectedName }
        try #require(injectedBinary != nil, "injected attachment missing")
        if case let .ref(idx) = injectedBinary?.value,
           Int(idx) < reread.innerHeader.binaryContent.count
        {
            #expect(reread.innerHeader.binaryContent[Int(idx)].data == injectedData)
        }
    }

    @Test(
        "Attachments written by keepassxc-cli read byte-perfect via KDBXReader",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func keePassXCAttachments_readableByUs() throws {
        // Seed from an existing 4.x fixture so the binary pool lives
        // in the inner header (KDBX 4 form) rather than Meta/Binaries
        // (KDBX 3.1 form, which kpxc-cli's db-create still defaults to
        // — see CLAUDE.md). Drive keepassxc-cli through several
        // attachment-import calls of varying sizes and re-open with
        // KDBXKit to assert every payload survived intact.
        let fixturePath = Bundle.module.path(forResource: "Resources/simple-argon2id-aes256", ofType: "kdbx")!
        let tmp = FileManager.default.temporaryDirectory
        let dbPath = tmp.appendingPathComponent("kpxc-attach-\(UUID().uuidString).kdbx").path
        try FileManager.default.copyItem(atPath: fixturePath, toPath: dbPath)
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        // The bundled fixture has one entry, "hello", under password "123".
        let entryName = "hello"
        let password = "123"
        let unlock = UnlockData(masterPassword: password)

        let imports: [(name: String, data: Data)] = [
            ("readme.txt", Data("KeePassXC -> KDBXKit attachment interop check\n".utf8)),
            ("blob-2k.bin", randomBytes(count: 2 * 1024)),
            ("blob-32k.bin", randomBytes(count: 32 * 1024)),
            ("unicode-name 测试.bin", Data([0x01, 0x02, 0x03, 0xFE, 0xFF])),
        ]

        var sourcePaths: [String] = []
        defer {
            for path in sourcePaths {
                try? FileManager.default.removeItem(atPath: path)
            }
        }

        for payload in imports {
            let src = tmp.appendingPathComponent("kpxc-attach-src-\(UUID().uuidString).bin").path
            sourcePaths.append(src)
            try payload.data.write(to: URL(filePath: src))

            let out = try runCLI(
                ["attachment-import", dbPath, entryName, payload.name, src],
                stdin: "\(password)\n"
            )
            #expect(
                !out.contains("ERROR"),
                "keepassxc-cli attachment-import failed for \(payload.name): \(out)"
            )
        }

        // Re-open with KDBXKit and verify every attachment KeePassXC
        // wrote shows up byte-perfect through our reader.
        let content = try KDBXReader.parse(
            try Data(contentsOf: URL(filePath: dbPath)),
            unlockData: unlock
        )
        let hello = content.database.root.group.entries.first { entry in
            entry.strings.first { $0.key == "Title" }?.value.bytes.withRevealedString { $0 } == entryName
        }
        try #require(hello != nil, "entry '\(entryName)' missing after keepassxc-cli mutations")

        for payload in imports {
            let binary = hello?.binaries.first { $0.key == payload.name }
            try #require(binary != nil, "attachment \(payload.name) not visible to KDBXReader")
            guard case let .ref(idx) = binary?.value else {
                Issue.record("attachment \(payload.name) was not stored as a pool ref")
                continue
            }
            try #require(
                Int(idx) < content.innerHeader.binaryContent.count,
                "attachment \(payload.name) ref index \(idx) out of bounds"
            )
            let pooled = content.innerHeader.binaryContent[Int(idx)]
            #expect(
                pooled.data == payload.data,
                "attachment \(payload.name) bytes mismatch (got \(pooled.data.count)B, expected \(payload.data.count)B)"
            )
        }

        // No silently-dropped XML pieces on the kpxc-produced file.
        #expect(
            content.parserWarnings.isEmpty,
            "unexpected parser warnings on KeePassXC output: \(content.parserWarnings)"
        )
    }

    @Test(
        "Empty (0-byte) attachment round-trips through keepassxc-cli intact",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func emptyAttachment_roundTrips() throws {
        // A 0-byte payload is the degenerate input for the streaming
        // gzip pipeline — DEFLATE with no input emits a minimal block,
        // and the inner-header binary entry has length 1 (the
        // shouldBeProtected flag byte + 0 data bytes). kpxc-extras
        // ships such a placeholder, but no interop test exercises
        // one. Write via us, export via kpxc, and read it back.
        let unlock = UnlockData(masterPassword: "empty")
        var content = KDBXContent.makeEmpty(databaseName: "EmptyAttach")

        content.innerHeader.binaryContent.append(.init(shouldBeProtected: false, data: Data()))
        let now = Date()
        var entry = KDBX.Entry(uuid: UUID(), times: .init(creationTime: now, lastModificationTime: now))
        entry.strings = [
            .init(key: "Title", value: .regular("Empty")),
            .init(key: "UserName", value: .regular("")),
            .init(key: "Password", value: .regular("")),
            .init(key: "URL", value: .regular("")),
            .init(key: "Notes", value: .regular("")),
        ]
        entry.binaries = [.init(key: "empty.bin", value: .ref(0))]
        content.database.root.group.entries.append(entry)

        let tmp = FileManager.default.temporaryDirectory
        let dbPath = tmp.appendingPathComponent("kdbxkit-empty-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let outputStream = OutputStream(toFileAtPath: dbPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        // kpxc must export it as a zero-byte file.
        let exportPath = tmp.appendingPathComponent("export-\(UUID().uuidString).bin").path
        defer { try? FileManager.default.removeItem(atPath: exportPath) }
        let out = try runCLI(
            ["attachment-export", dbPath, "Empty", "empty.bin", exportPath],
            stdin: "empty\n"
        )
        #expect(!out.contains("ERROR"), "kpxc attachment-export failed on empty attachment: \(out)")

        let exported = try Data(contentsOf: URL(filePath: exportPath))
        #expect(exported.isEmpty, "empty attachment exported as \(exported.count)-byte file")

        // And the reverse: kpxc imports a 0-byte file into our vault,
        // we re-read it, and the pool entry is still 0 bytes.
        let zeroSrc = tmp.appendingPathComponent("zero-\(UUID().uuidString).bin").path
        defer { try? FileManager.default.removeItem(atPath: zeroSrc) }
        try Data().write(to: URL(filePath: zeroSrc))
        let importOut = try runCLI(
            ["attachment-import", dbPath, "Empty", "second-empty.bin", zeroSrc],
            stdin: "empty\n"
        )
        #expect(!importOut.contains("ERROR"), "kpxc attachment-import failed on empty file: \(importOut)")

        let reread = try KDBXReader.parse(
            try Data(contentsOf: URL(filePath: dbPath)),
            unlockData: unlock
        )
        let probe = reread.database.root.group.entries.first { entry in
            entry.strings.first { $0.key == "Title" }?.value.bytes.withRevealedString { $0 } == "Empty"
        }
        try #require(probe != nil)
        let second = probe?.binaries.first { $0.key == "second-empty.bin" }
        try #require(second != nil, "kpxc-imported empty attachment missing")
        if case let .ref(idx) = second?.value, Int(idx) < reread.innerHeader.binaryContent.count {
            #expect(reread.innerHeader.binaryContent[Int(idx)].data.isEmpty)
        }
    }

    @Test(
        "Large (>1 MB) attachment crosses the HMAC block boundary and exports byte-perfect",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func largeAttachment_crossesHMACBlockBoundary() throws {
        // `HMACProtectedBlockStream` writes outer blocks of ~1 MB. A
        // 1.5 MB attachment forces at least one block boundary inside
        // the gzipped XML+binary stream. Anything wrong with our
        // multi-block framing — wrong block-HMAC, off-by-one length
        // field, missed flush — would surface as kpxc refusing to
        // open the file or the exported bytes diverging.
        let unlock = UnlockData(masterPassword: "big")
        var content = KDBXContent.makeEmpty(databaseName: "BigAttach")

        // 1.5 MB of incompressible bytes — well past the 1 MB outer
        // block size, and DEFLATE won't shrink it appreciably.
        let payload = randomBytes(count: 1_500_000)
        content.innerHeader.binaryContent.append(.init(shouldBeProtected: false, data: payload))

        let now = Date()
        var entry = KDBX.Entry(uuid: UUID(), times: .init(creationTime: now, lastModificationTime: now))
        entry.strings = [
            .init(key: "Title", value: .regular("Big")),
            .init(key: "UserName", value: .regular("")),
            .init(key: "Password", value: .regular("")),
            .init(key: "URL", value: .regular("")),
            .init(key: "Notes", value: .regular("")),
        ]
        entry.binaries = [.init(key: "big.bin", value: .ref(0))]
        content.database.root.group.entries.append(entry)

        let tmp = FileManager.default.temporaryDirectory
        let dbPath = tmp.appendingPathComponent("kdbxkit-big-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let outputStream = OutputStream(toFileAtPath: dbPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        let exportPath = tmp.appendingPathComponent("export-\(UUID().uuidString).bin").path
        defer { try? FileManager.default.removeItem(atPath: exportPath) }
        let out = try runCLI(
            ["attachment-export", dbPath, "Big", "big.bin", exportPath],
            stdin: "big\n"
        )
        #expect(!out.contains("ERROR"), "kpxc failed to export large attachment: \(out)")

        let exported = try Data(contentsOf: URL(filePath: exportPath))
        #expect(
            exported == payload,
            "large attachment differs after kpxc export (orig \(payload.count)B, got \(exported.count)B)"
        )
    }

    @Test(
        "Pool ref shared by two entries survives a keepassxc-cli round-trip",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func sharedAttachmentRef_survivesRoundTrip() throws {
        // KDBX's binary pool lets multiple entries point at the same
        // index. Our writer must not duplicate the payload on save,
        // and kpxc must serve the same bytes to whichever entry asks.
        // After a kpxc-driven re-encrypt, both entries' refs must
        // still resolve to bytes matching the original — whether kpxc
        // dedupes the pool or splits it into two copies is its choice
        // (the KDBX 4.1 spec allows either), so we assert byte-equality
        // per entry rather than pool cardinality.
        let unlock = UnlockData(masterPassword: "shared")
        var content = KDBXContent.makeEmpty(databaseName: "SharedAttach")

        let sharedPayload = randomBytes(count: 8 * 1024)
        content.innerHeader.binaryContent.append(.init(shouldBeProtected: false, data: sharedPayload))
        // Exactly one pool entry — sharing is the whole point.
        #expect(content.innerHeader.binaryContent.count == 1)

        let now = Date()
        func makeEntry(title: String) -> KDBX.Entry {
            var entry = KDBX.Entry(uuid: UUID(), times: .init(creationTime: now, lastModificationTime: now))
            entry.strings = [
                .init(key: "Title", value: .regular(title)),
                .init(key: "UserName", value: .regular("")),
                .init(key: "Password", value: .regular("")),
                .init(key: "URL", value: .regular("")),
                .init(key: "Notes", value: .regular("")),
            ]
            entry.binaries = [.init(key: "shared.bin", value: .ref(0))]
            return entry
        }
        content.database.root.group.entries.append(makeEntry(title: "Alpha"))
        content.database.root.group.entries.append(makeEntry(title: "Beta"))

        let tmp = FileManager.default.temporaryDirectory
        let dbPath = tmp.appendingPathComponent("kdbxkit-shared-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: dbPath) }

        let outputStream = OutputStream(toFileAtPath: dbPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        // Before any kpxc rewrite: both entries export identical bytes.
        for entryName in ["Alpha", "Beta"] {
            let exportPath = tmp.appendingPathComponent("export-\(UUID().uuidString).bin").path
            defer { try? FileManager.default.removeItem(atPath: exportPath) }
            let out = try runCLI(
                ["attachment-export", dbPath, entryName, "shared.bin", exportPath],
                stdin: "shared\n"
            )
            #expect(!out.contains("ERROR"), "kpxc export failed for \(entryName): \(out)")
            let exported = try Data(contentsOf: URL(filePath: exportPath))
            #expect(
                exported == sharedPayload,
                "shared attachment bytes diverged for \(entryName)"
            )
        }

        // Force kpxc to load + re-save the file (attachment-import
        // is the cheapest re-encrypting mutation). The injected
        // attachment goes on a third entry to keep Alpha/Beta's refs
        // untouched on the kpxc side.
        let probePath = tmp.appendingPathComponent("probe-\(UUID().uuidString).bin").path
        defer { try? FileManager.default.removeItem(atPath: probePath) }
        try Data("probe".utf8).write(to: URL(filePath: probePath))
        let importOut = try runCLI(
            ["attachment-import", dbPath, "Alpha", "probe.bin", probePath],
            stdin: "shared\n"
        )
        #expect(!importOut.contains("ERROR"), "kpxc attachment-import failed: \(importOut)")

        // Re-open with KDBXKit. Each entry's shared.bin ref must still
        // resolve to bytes matching the original payload.
        let reread = try KDBXReader.parse(
            try Data(contentsOf: URL(filePath: dbPath)),
            unlockData: unlock
        )
        for entryName in ["Alpha", "Beta"] {
            let found = reread.database.root.group.entries.first { entry in
                entry.strings.first { $0.key == "Title" }?.value.bytes.withRevealedString { $0 } == entryName
            }
            try #require(found != nil, "\(entryName) entry vanished after kpxc re-save")
            let shared = found?.binaries.first { $0.key == "shared.bin" }
            try #require(shared != nil, "shared.bin missing on \(entryName)")
            guard case let .ref(idx) = shared?.value else {
                Issue.record("\(entryName)'s shared.bin was not stored as a ref after re-save")
                continue
            }
            try #require(
                Int(idx) < reread.innerHeader.binaryContent.count,
                "\(entryName)'s shared.bin ref \(idx) out of bounds"
            )
            #expect(
                reread.innerHeader.binaryContent[Int(idx)].data == sharedPayload,
                "\(entryName)'s shared.bin bytes diverged after kpxc re-save"
            )
        }
    }

    @Test(
        "KDBX 3.1 vault migrated to 4.1 (default KDF preservation) is readable by keepassxc-cli",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func kdbx31_migratedTo4x_readableByKeePassXC() throws {
        // The internal round-trip test (StaticReaderAPITests) proves
        // we can re-read our own output. This proves the migrated
        // file is a spec-compliant 4.x file the canonical kpxc binary
        // can decrypt — the only test that catches KDBX-format-spec
        // divergences in our writer when the source was 3.x.
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "test")

        let content = try KDBXReader.parse(data, unlockData: unlock)
        #expect(content.header.formatVersion == .v3_1, "fixture sanity: source must be 3.x")

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-3x-migrated-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }

        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        let output = try runCLI(["show", "-s", outPath, "Example Login"], stdin: "test\n")
        #expect(output.contains("Title: Example Login"))
        #expect(output.contains("UserName: alice"))
        #expect(output.contains("URL: https://example.com"))
        // The protected Password field must decrypt under kpxc — proves
        // the ChaCha20-aware inner-cipher serialization path emits
        // bytes whose XOR layout kpxc reads correctly. (The migrated
        // file inherits the 3.x Salsa20 inner cipher, which kpxc
        // accepts as a valid 4.x option.)
        #expect(output.contains("Password: secret123"))
    }

    @Test(
        "KDBX 3.1 vault migrated to Argon2id is readable by keepassxc-cli",
        .enabled(if: KeePassXCInteropTests.cliAvailable, "KeePassXC CLI not installed")
    )
    func kdbx31_upgradedToArgon2id_readableByKeePassXC() throws {
        // The Argon2id upgrade is the migration Passie applies to 3.x
        // vaults on first save — it's the user-facing point of
        // supporting 3.x at all. This test proves the upgraded file
        // is structurally valid: header, KDF identity, and the
        // serialized Argon2id VariantDictionary all pass kpxc's
        // stricter parser, and the user's original master password
        // still unlocks it after the KDF swap.
        let path = Bundle.module.path(forResource: "Resources/kpxc-kdbx31-default", ofType: "kdbx")!
        let data = try Data(contentsOf: URL(filePath: path))
        let unlock = UnlockData(masterPassword: "test")

        var content = try KDBXReader.parse(data, unlockData: unlock)
        // The standard default keeps the unlock fast (t=3, 64 MiB) —
        // this test runs the KDF twice (write + kpxc decrypt), so don't
        // burn time on a heavier setting just to prove the migration is
        // well-formed.
        content.upgradeToArgon2id()

        let outPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("kdbxkit-3x-argon2id-\(UUID().uuidString).kdbx").path
        defer { try? FileManager.default.removeItem(atPath: outPath) }

        let outputStream = OutputStream(toFileAtPath: outPath, append: false)!
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock)
        outputStream.close()

        let output = try runCLI(["show", "-s", outPath, "Example Login"], stdin: "test\n")
        #expect(output.contains("Title: Example Login"))
        #expect(
            output.contains("Password: secret123"),
            "kpxc must accept Argon2id-derived unlock key against the unchanged master password"
        )
    }

    /// Deterministic-enough random bytes for tests — uses
    /// `SystemRandomNumberGenerator` because we only need uniqueness
    /// within a single test invocation, not across runs.
    private func randomBytes(count: Int) -> Data {
        var rng = SystemRandomNumberGenerator()
        var buf = Data(count: count)
        buf.withUnsafeMutableBytes { raw in
            var i = raw.bindMemory(to: UInt64.self).baseAddress!
            let fullWords = count / 8
            for _ in 0..<fullWords {
                i.pointee = rng.next()
                i = i.advanced(by: 1)
            }
            let tail = count - fullWords * 8
            if tail > 0 {
                var word = rng.next()
                let tailStart = raw.baseAddress!.advanced(by: fullWords * 8)
                withUnsafeBytes(of: &word) { src in
                    for j in 0..<tail {
                        tailStart.advanced(by: j).storeBytes(of: src[j], as: UInt8.self)
                    }
                }
            }
        }
        return buf
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
