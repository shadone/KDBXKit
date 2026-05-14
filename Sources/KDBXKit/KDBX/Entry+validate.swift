//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public extension KDBX.Entry {
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

        validateDateIsRecommended(times?.creationTime, in: "Entry[\(uuid.uuidString)].Times.CreationTime")
        validateDateIsInFuture(times?.creationTime, in: "Entry[\(uuid.uuidString)].Times.CreationTime")

        validateDateIsRecommended(times?.lastModificationTime, in: "Entry[\(uuid.uuidString)].Times.LastModificationTime")
        validateDateIsInFuture(times?.lastModificationTime, in: "Entry[\(uuid.uuidString)].Times.LastModificationTime")

        validateDateIsInFuture(times?.lastAccessTime, in: "Entry[\(uuid.uuidString)].Times.LastAccessTime")

        validateDateIsInFuture(times?.locationChanged, in: "Entry[\(uuid.uuidString)].Times.LocationChanged")

        var allStringKeys: Set<String> = []
        for protectedString in strings {
            // Check all ProtectedStrings have unique key
            if allStringKeys.contains(protectedString.key) {
                results.append(.warning("Entry[\(uuid.uuidString)].Strings have duplicate keys: \(protectedString.key)"))
            }
            allStringKeys.insert(protectedString.key)

            if protectedString.key == "Title" {
                // Check that the Title key is *not* unprotected
                switch protectedString.value {
                case .protectedInMemory:
                    results.append(.warning("Entry[\(uuid.uuidString)].Strings[Title] type is ProtectInMemory, recommended to be regular"))

                case .unprotected, .lazyInnerCipher:
                    results.append(.warning("Entry[\(uuid.uuidString)].Strings[Title] type is Protected, recommended to be regular"))

                case .regular:
                    // That's what we want!
                    break
                }
            }

            if protectedString.key == "Password" {
                // Check that Password key *is* protected
                switch protectedString.value {
                case .protectedInMemory:
                    results.append(.warning("Entry[\(uuid.uuidString)].Strings[Password] type is ProtectInMemory, recommended to be Protected"))

                case .unprotected, .lazyInnerCipher:
                    // That's what we want — the on-disk form is the
                    // inner-cipher-encrypted ciphertext, regardless of
                    // whether we kept it lazy in memory.
                    break

                case .regular:
                    results.append(.warning("Entry[\(uuid.uuidString)].Strings[Password] type is Regular, recommended to be Protected"))
                }
            }
        }
        // Check that the Entry has Title key
        if !allStringKeys.contains("Title") {
            results.append(.warning("Entry[\(uuid.uuidString)].Strings does not have a Title"))
        }

        var allBinariesKeys: Set<String> = []
        for protectedBinary in binaries {
            // Check all ProtectedBinaries have unique key
            if allBinariesKeys.contains(protectedBinary.key) {
                results.append(.warning("Entry[\(uuid.uuidString)].Binaries have duplicate keys: \(protectedBinary.key)"))
            }
            allBinariesKeys.insert(protectedBinary.key)
        }

        for historicalEntry in history {
            // Check that History points to the same Entry
            if historicalEntry.uuid != uuid {
                results.append(.warning("Entry[\(uuid.uuidString)].History has element with a different UUID"))
            }
            // Check that History element does not have own History
            if !historicalEntry.history.isEmpty {
                results.append(.warning("Entry[\(uuid.uuidString)].History has element has own History"))
            }
        }

        return results
    }
}
