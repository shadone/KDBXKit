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

    @Test("`mutating func` extension that mutates customData fires didSet on the caller's meta")
    func mutatingFuncExtensionFiresDidSet() {
        // Mirrors the Passie-side `Meta+Passie.swift` shape:
        // a `mutating func` extension on KDBX.Meta whose body
        // mutates a stored property (`customData` here) via the
        // Array's mutating methods. Confirms that didSet on
        // customData fires through that indirection — if it
        // didn't, every Passie-side `setPassieVaultID` /
        // `setTrashRetentionDays` call would land on disk with a
        // stale settingsChanged.
        var meta = KDBX.Meta()
        meta._test_addCustomData(key: "demo", value: "x")
        #expect(meta.settingsChanged != nil)
        #expect(meta.customData.count == 1)
    }

    @Test("`mutating func` extension that mutates customIcons fires didSet")
    func mutatingFuncExtensionOnCustomIconsFiresDidSet() {
        var meta = KDBX.Meta()
        meta._test_addCustomIcon()
        #expect(meta.settingsChanged != nil)
        #expect(meta.customIcons.count == 1)
    }

    @Test("Chained mutation through a class property still fires didSet on the inner struct")
    func chainedClassPropertyMutationFiresDidSet() {
        // Stand-in for `vault.meta.customIcons.append(...)` in
        // `Vault.setCustomIcon`. `Vault` is a class; `meta` is a
        // stored `KDBX.Meta` value-type property. Swift's
        // materialize-inout chain has to round-trip back through
        // the property's setter for didSet to fire.
        let box = _MetaBox()
        box.meta.customIcons.append(
            KDBX.CustomIcon(uuid: UUID(), data: Data([1]), name: nil, lastModificationTime: Date())
        )
        #expect(box.meta.settingsChanged != nil)
    }
}

// MARK: - Test helpers

private final class _MetaBox {
    var meta = KDBX.Meta()
}

private extension KDBX.Meta {
    mutating func _test_addCustomData(key: String, value: String) {
        customData.removeAll(where: { $0.key == key })
        customData.append(.init(key: key, value: value, lastModificationTime: Date()))
    }

    mutating func _test_addCustomIcon() {
        customIcons.append(
            KDBX.CustomIcon(uuid: UUID(), data: Data([1]), name: nil, lastModificationTime: Date())
        )
    }

    @Test("Re-stamping generator with the same value does not bump settingsChanged")
    func sameGeneratorIsNoOp() {
        let onDisk = Date(timeIntervalSince1970: 1_700_000_000)
        var meta = KDBX.Meta(generator: "Passie", settingsChanged: onDisk)
        meta.generator = "Passie"
        #expect(meta.settingsChanged == onDisk)
    }

    @Test("Changing generator (cross-client save) bumps settingsChanged")
    func generatorChangeBumpsSettings() {
        var meta = KDBX.Meta(generator: "KeePassXC")
        let before = Date()
        meta.generator = "Passie"
        let after = Date()
        #expect((before...after).contains(meta.settingsChanged!))
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

    // MARK: - Idempotent-write guard

    //
    // `didSet` guards on `oldValue != current` so reassigning a field
    // with its existing value is a true no-op (no stamp advance).
    // Without this, defensive re-application during deserialise →
    // re-serialise paths would falsely register as edits and lose
    // against a real edit on the other side of a sync.

    @Test("Re-assigning databaseName with the same value does not bump settingsChanged")
    func sameValueAssignmentIsNoOp() {
        let onDisk = Date(timeIntervalSince1970: 1_700_000_000)
        var meta = KDBX.Meta(
            settingsChanged: onDisk,
            databaseName: "Wallet",
            databaseNameChanged: onDisk
        )
        meta.databaseName = "Wallet"
        #expect(meta.settingsChanged == onDisk)
        #expect(meta.databaseNameChanged == onDisk)
    }

    @Test("Re-assigning recycleBinUUID with the same value does not bump recycleBinChanged")
    func sameRecycleBinUUIDIsNoOp() {
        let onDisk = Date(timeIntervalSince1970: 1_700_000_000)
        let uuid = UUID()
        var meta = KDBX.Meta(
            settingsChanged: onDisk,
            recycleBinUUID: uuid,
            recycleBinChanged: onDisk
        )
        meta.recycleBinUUID = uuid
        #expect(meta.settingsChanged == onDisk)
        #expect(meta.recycleBinChanged == onDisk)
    }

    @Test("Re-assigning color with the same value does not bump settingsChanged")
    func sameColorIsNoOp() {
        let onDisk = Date(timeIntervalSince1970: 1_700_000_000)
        let color: KDBX.Color = .color(red: 0x4F, green: 0x7E, blue: 0x62)
        var meta = KDBX.Meta(settingsChanged: onDisk, color: color)
        meta.color = color
        #expect(meta.settingsChanged == onDisk)
    }

    @Test("Actually changing the value still bumps after a prior no-op write")
    func realChangeAfterNoOpStillBumps() {
        let onDisk = Date(timeIntervalSince1970: 1_700_000_000)
        var meta = KDBX.Meta(
            settingsChanged: onDisk,
            databaseName: "Wallet",
            databaseNameChanged: onDisk
        )
        meta.databaseName = "Wallet" // no-op
        #expect(meta.settingsChanged == onDisk)

        let before = Date()
        meta.databaseName = "Banking" // real change
        let after = Date()
        #expect((before...after).contains(meta.settingsChanged!))
        #expect((before...after).contains(meta.databaseNameChanged!))
    }
}
