//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX.Meta {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        func validateDateIsInFuture(_ date: Date?, in nodeName: String) {
            if let date, date > Date() {
                results.append(.warning("\(nodeName) should not be in future: \(date)"))
            }
        }
        func validateDateIsRecommended(_ date: Date?, in nodeName: String) {
            if date == nil {
                results.append(.warning("\(nodeName) is recommended to be set"))
            }
        }

        if generator?.isEmpty ?? true {
            results.append(.warning("Meta.Generator is recommended to be set to a unique value"))
        }

        if let headerHash, !headerHash.isEmpty {
            results.append(.warning("Meta.HeaderHash should not be used for KDBX v4 or newer"))
        }

        validateDateIsRecommended(settingsChanged, in: "Meta.SettingsChanged")
        validateDateIsInFuture(settingsChanged, in: "Meta.SettingsChanged")

        if databaseName?.isEmpty ?? true {
            results.append(.warning("Meta.DatabaseName is recommended to be set"))
        }

        validateDateIsRecommended(databaseNameChanged, in: "Meta.DatabaseNameChanged")
        validateDateIsInFuture(databaseNameChanged, in: "Meta.DatabaseNameChanged")

        // if Recycle Bin is enabled, it should have UUID assigned
        if recycleBinEnabled ?? false {
            if recycleBinUUID == nil {
                results.append(.warning("Meta.RecycleBinUUID is required when the Meta.RecycleBinEnabled is true"))
            }

            validateDateIsRecommended(recycleBinChanged, in: "Meta.RecycleBinChanged")
            validateDateIsInFuture(recycleBinChanged, in: "Meta.RecycleBinChanged")
        }

        if entryTemplatesGroup != nil {
            validateDateIsRecommended(entryTemplatesGroupChanged, in: "Meta.EntryTemplatesGroupChanged")
            validateDateIsInFuture(entryTemplatesGroupChanged, in: "Meta.EntryTemplatesGroupChanged")
        }

        return results
    }
}
