//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

struct Info: ParsableCommand {
    @OptionGroup()
    var commonOptions: CommonOptions

    mutating func run() throws {
        let kdbx: KDBXReader
        let content: KDBXContent?
        let hasUnlockDataButNotCorrect: Bool

        switch try read(from: commonOptions.filepath, unlockData: commonOptions.unlockData) {
        case let .invalidUnlockData(kdxReader):
            kdbx = kdxReader
            content = nil
            hasUnlockDataButNotCorrect = true

        case let .success(kdbxContent, kdbxReader):
            kdbx = kdbxReader
            content = kdbxContent
            hasUnlockDataButNotCorrect = false
        }

        guard let header = kdbx.header else {
            fatalError("Internal error: should have the header after parsing")
        }

        print("Format version: \(header.formatVersion)")
        print("Encryption algorithm: \(header.encryptionAlgorithm)")
        print("Compression algorithm: \(header.compressionAlgorithm.description)")
        print("Master salt/seed: \(header.masterSalt.hexString)")
        print("Encryption nonce/iv: \(header.encryptionNonce.hexString)")

        print("KDF parameters:")
        switch header.kdfParameters {
        case let .aes(aes, additional):
            print("\tSalt: \(aes.salt.hexString)")
            print("\tRounds: \(aes.rounds)")
            if !additional.isEmpty {
                print("\tAdditional data: \(additional)")
            }

        case let .argon2d(argon2, additional), let .argon2id(argon2, additional):
            if case .argon2d = header.kdfParameters {
                print("\tType: Argon2d")
            } else {
                print("\tType: Argon2id")
            }
            print("\tVersion: \(argon2.version)")
            print("\tSalt: \(argon2.salt.hexString)")
            print("\tMemory cost: \(argon2.memory / 1024)KiB")
            print("\tParallelism cost: \(argon2.parallelism)")
            print("\tIterations: \(argon2.iterations)")
            if !additional.isEmpty {
                print("\tAdditional data: \(additional)")
            }

        case let .unknown(uuid):
            print("Unknown kdf: \(uuid.uuidString)")
        }

        if !header.publicCustomData.isEmpty {
            print("Public custom data:")
            for (key, value) in header.publicCustomData {
                print("\t\(key): \(value)")
            }
        }

        if hasUnlockDataButNotCorrect {
            print("")
            print("Error: The specified master password is not correct.")
        }

        if !kdbx.blockSizes.isEmpty {
            print("")

            print("Block stream sizes: \(kdbx.blockSizes)")
        }

        if let innerHeader = kdbx.innerHeader {
            print("")

            print("Inner Header:")
            print("\tEncryption Algorithm: \(innerHeader.encryptionAlgorithm)")
            print("\tEncryption key: \(innerHeader.encryptionKey.toData().hexString)")
            print("\tBinary Content: \(innerHeader.binaryContent.count) elements")
            for (index, element) in innerHeader.binaryContent.enumerated() {
                print("\t\t\(index): \(element.data.count) bytes" + (element.shouldBeProtected ? " [protected]" : ""))
            }
        }

        let issues = content?.validate() ?? []
        if !issues.isEmpty {
            print("")
            print("Validation issues:")
            for issue in issues {
                print("\t \(issue.level.description): \(issue.message)")
            }
        }
    }
}
