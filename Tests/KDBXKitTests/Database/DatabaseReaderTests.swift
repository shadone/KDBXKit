//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct DatabaseTests {
    @Test
    func DatabaseReader_empty() async throws {
        let xmlFilepath = Bundle.module.path(forResource: "Resources/database-encrypted-empty", ofType: "xml")!
        let xmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)

        let reader = DatabaseReader(xmlDocument: xmlDocument)
        let database = try reader.parse()

        #expect(database.meta.generator == "KeePassXC")
        #expect(database.meta.databaseName == "test3")
        #expect(database.meta.databaseNameChanged == Date(timeIntervalSince1970: 1_747_996_682))
        #expect(database.meta.maintenanceHistoryDays == 365)
    }

    @Test
    func writeThenRead() throws {
        let mockDate = Date(secondsSinceDotNetEpoch: 63884389441)

        let reference = Database(
            meta: .init(
                generator: "KDBXKit",
                settingsChanged: mockDate,
                databaseName: "Test Database",
                databaseNameChanged: mockDate,
                databaseDescription: "test database description",
                databaseDescriptionChanged: mockDate,
                defaultUserName: "hello",
                defaultUserNameChanged: mockDate,
                maintenanceHistoryDays: 123,
                color: .color(red: 12, green: 23, blue: 45),
                masterKeyChanged: mockDate,
                masterKeyChangeRec: .never,
                masterKeyChangeForce: .value(42),
                masterKeyChangeForceOnce: false,
                memoryProtection: .init(
                    protectTitle: false,
                    protectUserName: true,
                    protectPassword: false,
                    protectURL: true,
                    protectNotes: false,
                ),
                customIcons: [
                    .init(
                        uuid: UUID(),
                        data: Data([1,2,3]),
                        name: "Test Icon",
                        lastModificationTime: mockDate,
                    ),
                ],
                recycleBinEnabled: true,
                recycleBinUUID: UUID(),
                recycleBinChanged: mockDate,
                entryTemplatesGroup: UUID(),
                entryTemplatesGroupChanged: mockDate,
                historyMaxSize: .value(123),
                lastSelectedGroup: UUID(),
                lastTopVisibleGroup: UUID(),
                customData: [
                    .init(key: "Foo", value: "Bar"),
                    .init(key: "Hello", value: "World", lastModificationTime: mockDate),
                ],
            ),
            root: .init(
                group: .init(
                    uuid: UUID(),
                    name: "Root Group",
                    notes: "here goes notes",
                    iconID: 123,
                    customIconUUID: UUID(),
                    times: .init(
                        creationTime: mockDate,
                        lastModificationTime: mockDate,
                        lastAccessTime: mockDate,
                        expiryTime: mockDate,
                        expires: false,
                        usageCount: 123456,
                        locationChanged: mockDate,
                    ),
                    isExpanded: true,
                    defaultAutoTypeSequence: "foo",
                    enableAutoType: .value(true),
                    enableSearching: .null,
                    lastTopVisibleEntry: UUID(),
                    previousParentGroup: UUID(),
                    tags: ["one", "two"],
                    customData: [
                        .init(key: "Hello", value: "World"),
                    ],
                    entries: [
                    ],
                    groups: [
                    ],
                ),
                deletedObjects: [],
            )
        )

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        let writer = DatabaseWriter(to: outputStream)
        try writer.write(reference)

        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let xmlDocument = String(data: data, encoding: .utf8)!
        print(xmlDocument)

        let reader = DatabaseReader(xmlDocument: xmlDocument)
        let parsed = try reader.parse()

        #expect(parsed == reference)
    }
}
