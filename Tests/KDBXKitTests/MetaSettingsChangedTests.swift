//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Suite("KDBX.Meta — settingsChanged invariant")
struct MetaSettingsChangedTests {

    @Test("init does not bump settingsChanged — preserves on-disk timestamps verbatim")
    func initDoesNotBump() {
        let onDisk = Date(timeIntervalSince1970: 1_700_000_000)
        let meta = KDBX.Meta(
            settingsChanged: onDisk,
            databaseName: "Wallet",
            databaseNameChanged: onDisk,
            color: .color(red: 0x4F, green: 0x7E, blue: 0x62),
            customIcons: [],
            recycleBinEnabled: true,
            customData: []
        )
        #expect(meta.settingsChanged == onDisk)
        #expect(meta.databaseNameChanged == onDisk)
    }

    @Test("Mutating databaseName bumps databaseNameChanged AND settingsChanged")
    func databaseNameBumpsBoth() {
        var meta = KDBX.Meta()
        let before = Date()
        meta.databaseName = "Wallet"
        let after = Date()

        #expect(meta.settingsChanged != nil)
        #expect(meta.databaseNameChanged != nil)
        #expect((before...after).contains(meta.settingsChanged!))
        #expect((before...after).contains(meta.databaseNameChanged!))
    }

    @Test("Mutating an untracked field (color) bumps only settingsChanged")
    func untrackedFieldBumpsSettingsOnly() {
        var meta = KDBX.Meta()
        let before = Date()
        meta.color = .color(red: 0x82, green: 0xB0, blue: 0x97)
        let after = Date()

        #expect((before...after).contains(meta.settingsChanged!))
        #expect(meta.databaseNameChanged == nil) // unrelated companion untouched
    }

    @Test("Setting masterKeyChanged bumps settingsChanged")
    func masterKeyChangedBumpsSettings() {
        var meta = KDBX.Meta()
        meta.masterKeyChanged = Date()
        #expect(meta.settingsChanged != nil)
    }

    @Test("Mutating customIcons (append) bumps settingsChanged")
    func customIconAppendBumps() {
        var meta = KDBX.Meta()
        meta.customIcons.append(
            KDBX.CustomIcon(uuid: UUID(), data: Data([1, 2, 3]), name: "demo", lastModificationTime: Date())
        )
        #expect(meta.settingsChanged != nil)
    }

    @Test("Mutating customIcons (removeAll) bumps settingsChanged")
    func customIconRemoveBumps() {
        // Start populated via the init (no didSet on initial assignment).
        let icon = KDBX.CustomIcon(uuid: UUID(), data: Data([1]), name: "x", lastModificationTime: Date())
        var meta = KDBX.Meta(customIcons: [icon])
        #expect(meta.settingsChanged == nil)

        meta.customIcons.removeAll { $0.uuid == icon.uuid }
        #expect(meta.settingsChanged != nil)
    }

    @Test("Mutating customData bumps settingsChanged")
    func customDataMutationBumps() {
        var meta = KDBX.Meta()
        meta.customData.append(.init(key: "passie:vaultID", value: "abc", lastModificationTime: Date()))
        #expect(meta.settingsChanged != nil)
    }

    @Test("Stamping generator does NOT bump settingsChanged — writer-stamped every save")
    func generatorDoesNotBump() {
        var meta = KDBX.Meta()
        meta.generator = "Passie"
        #expect(meta.settingsChanged == nil)
    }

    @Test("Stamping headerHash does NOT bump settingsChanged — legacy/internal field")
    func headerHashDoesNotBump() {
        var meta = KDBX.Meta()
        meta.headerHash = "abc123"
        #expect(meta.settingsChanged == nil)
    }

    @Test("Round-trip through XML preserves on-disk settingsChanged verbatim")
    func roundTripPreservesSettingsChanged() throws {
        // The didSet on every other field would clobber this if the
        // reader populated Meta incrementally. Guards against the bug.
        let onDisk = Date(timeIntervalSince1970: 1_650_000_000)
        var content = KDBXContent.makeEmpty(databaseName: "Vault", generator: "Test")
        content.database.meta = KDBX.Meta(
            generator: "Test",
            settingsChanged: onDisk,
            databaseName: "Vault",
            databaseNameChanged: onDisk,
            color: .color(red: 1, green: 2, blue: 3),
            recycleBinEnabled: true
        )

        let unlock = UnlockData(masterPassword: "test")
        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        try KDBXWriter(to: outputStream).write(content, unlockData: unlock, regenerateSalts: false)
        let bytes = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let parsed = try KDBXReader.parse(bytes, unlockData: unlock)

        #expect(parsed.database.meta.settingsChanged == onDisk)
        #expect(parsed.database.meta.databaseNameChanged == onDisk)
    }
}
