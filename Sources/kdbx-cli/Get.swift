//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

struct Get: ParsableCommand {
    @OptionGroup()
    var commonOptions: CommonOptions

    mutating func run() throws {
        guard
            case let .success(content, _) = try read(from: commonOptions.filepath, unlockData: commonOptions.unlockData)
        else {
            throw AppError.invalidUnlockData
        }

        content.database.visitEntries(in: content.database.root.group) { entry in
            print("")
            print("Entry: \(entry.uuid)")

            for string in entry.strings {
                let name = string.key
                let value: String
                let valueType: String

                switch string.value {
                case let .unprotected(b):
                    value = b.revealedString
                    valueType = "[*]"

                case let .regular(b):
                    value = b.revealedString
                    valueType = ""

                case let .protectedInMemory(b):
                    value = b.revealedString
                    valueType = "[M]"

                case .lazyInnerCipher:
                    value = string.value.revealedString
                    valueType = "[*]"
                }

                print("\t\(name)\(valueType): \(value)")
            }

            if !entry.binaries.isEmpty {
                print("\tBinaries:")
                for binary in entry.binaries {
                    let name = binary.key
                    switch binary.value {
                    case let .inline(data):
                        print("\t\t\(name): \(data.count) bytes")
                    case let .ref(ref):
                        let data = content.innerHeader.binaryContent[Int(ref)].data
                        print("\t\t\(name): ref=\(ref): \(data.count) bytes")
                    }
                }
            }
        }
    }
}
