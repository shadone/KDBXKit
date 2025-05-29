//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

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
