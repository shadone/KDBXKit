//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import ArgumentParser
import Foundation
import KDBXKit

@main
struct App: ParsableCommand {
    @Argument(help: "The .kdbx file to open")
    var filepath: String

    @Argument(help: "The master password to use")
    var masterPassword: String?

    var unlockData: UnlockData? {
        if let masterPassword {
            return .init(masterPassword: masterPassword)
        }
        return nil
    }

    mutating func run() throws {
        let data = try! Data(contentsOf: URL(filePath: filepath))

        var kdbx = KDBXReader(data)
        let xmlDocument: String?
        /// The master password was specified but is not correct.
        let hasUnlockDataButNotCorrect: Bool

        do {
            _ = try kdbx.parse(unlockData: unlockData)
            xmlDocument = kdbx.xmlDocument
            hasUnlockDataButNotCorrect = false
        } catch {
            xmlDocument = nil
            switch error {
            case .invalidUnlockData:
                if unlockData != nil {
                    // The master password was given but doesn't match the password used for encryption
                    hasUnlockDataButNotCorrect = true
                } else {
                    // No master password was given, we didn't even try to decrypt the content
                    hasUnlockDataButNotCorrect = false
                }
            case let .unsupported(reason):
                print("The specified KDBX file is not supported: \(reason)")
                return
            case let .corrupted(reason):
                print("Failed to parse KDBX file: \(reason)")
                return
            case .unexpectedEOF:
                print("Failed to parse KDBX file: unexpected end of file")
                return
            }
        }

        guard let header = kdbx.header else {
            fatalError("Internal error: should have the header after parsing")
        }

        print("Format version: \(header.formatVersion)")
        print("Encryption algorithm: \(header.encryptionAlgorithm)")
        print("Compression algorithm: \(header.compressionAlgorithm?.description ?? "none")")
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
            print("\tEncryption key: \(innerHeader.encryptionKey.hexString)")
            print("\tBinary Content: \(innerHeader.binaryContent.count) elements")
            for (index, element) in innerHeader.binaryContent.enumerated() {
                print("\t\t\(index): \(element.data.count) bytes" + (element.shouldBeProtected ? " [protected]" : ""))
            }
        }

        if let xmlDocument {
            print("")

            print(xmlDocument)
        }
    }
}
