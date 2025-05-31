//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBXContent {
    func validate() -> [ValidationFailure] {
        var results: [ValidationFailure] = []

        results += database.validate()
        results += header.validate()
        results += innerHeader.validate()

        // Check that ProtectedBinaries Ref points to the existing Binary
        let numberOfBinaries = UInt32(innerHeader.binaryContent.count)
        database.visitEntries(in: database.root.group) { entry in
            for binary in entry.binaries {
                switch binary.value {
                case .ref(let ref):
                    if ref >= numberOfBinaries {
                        results.append(.warning("Entry[\(entry.uuid)].Binaries Ref=\(ref) points to a non-existing Binary"))
                    }

                case .inline:
                    // Ok
                    break
                }
            }
        }

        return results
    }
}
