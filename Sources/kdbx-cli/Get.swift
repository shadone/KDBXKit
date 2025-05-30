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
            case var .success(content, _) = try read(from: commonOptions.filepath, unlockData: commonOptions.unlockData)
        else {
            throw AppError.invalidUnlockData
        }

        try content.decrypt()

        content.database.visitEntries(in: content.database.root.group) { entry in
            print("")
            print("Entry: \(entry.uuid)")

            for string in entry.strings {
                let name = string.key
                let value: String

                switch string.value {
                case .unprotected(let v):
                    value = v

                case .regular(let v):
                    value = v

                case .protectedInMemory(let v):
                    value = v

                case .protected:
                    preconditionFailure("The value should have been decrypted already")
                }

                print("\t\(name): \(value)")
            }

            if !entry.binaries.isEmpty {
                print("\tBinaries:")
                for binary in entry.binaries {
                    let name = binary.key
                    switch binary.value {
                    case .inline(let data):
                        print("\t\t\(name): \(data.count) bytes")
                    case .ref(let ref):
                        let data = content.innerHeader.binaryContent[Int(ref)].data
                        print("\t\t\(name): ref=\(ref): \(data.count) bytes")
                    }
                }
            }
        }
    }
}
