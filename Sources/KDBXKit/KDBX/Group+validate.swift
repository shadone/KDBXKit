//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX.Group {
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

        if name?.isEmpty ?? true {
            results.append(.warning("Group[\(uuid.uuidString)].Name is recommended to be set"))
        }

        validateDateIsRecommended(times?.creationTime, in: "Group[\(uuid.uuidString)].Times.CreationTime")
        validateDateIsInFuture(times?.creationTime, in: "Group[\(uuid.uuidString)].Times.CreationTime")

        validateDateIsRecommended(times?.lastModificationTime, in: "Group[\(uuid.uuidString)].Times.LastModificationTime")
        validateDateIsInFuture(times?.lastModificationTime, in: "Group[\(uuid.uuidString)].Times.LastModificationTime")

        validateDateIsInFuture(times?.lastAccessTime, in: "Group[\(uuid.uuidString)].Times.LastAccessTime")

        validateDateIsInFuture(times?.locationChanged, in: "Group[\(uuid.uuidString)].Times.LocationChanged")

        return results
    }
}
