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

        // Check that ProtectedBinaries Ref points to the existing Binary.
        // History snapshots carry their own binaries and reference the
        // same inner-header pool, so they're validated too — a dangling
        // ref in a history entry is just as corrupt as one on the live
        // entry, and the save-time pool remap touches both.
        let numberOfBinaries = UInt32(innerHeader.binaryContent.count)
        func validateBinaries(of entry: KDBX.Entry, context: String) {
            for binary in entry.binaries {
                if case let .ref(ref) = binary.value, ref >= numberOfBinaries {
                    results.append(.warning("\(context).Binaries Ref=\(ref) points to a non-existing Binary"))
                }
            }
        }
        database.visitEntries(in: database.root.group) { entry in
            validateBinaries(of: entry, context: "Entry[\(entry.uuid)]")
            for historic in entry.history {
                validateBinaries(of: historic, context: "Entry[\(entry.uuid)].History")
            }
        }

        return results
    }
}
