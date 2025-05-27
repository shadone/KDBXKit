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

    var reader = DatabaseReader(xmlDocument: xmlDocument)
    try reader.parse()

    #expect(reader.meta.generator == "KeePassXC")
    #expect(reader.meta.databaseName == "test3")
    #expect(reader.meta.databaseNameChanged == Date(timeIntervalSince1970: 1_747_996_682))
    #expect(reader.meta.maintenanceHistoryDays == 365)
}
