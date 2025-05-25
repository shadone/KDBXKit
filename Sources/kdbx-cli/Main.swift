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
    var masterPassword: String

    mutating func run() throws {
        let data = try! Data(contentsOf: URL(filePath: filepath))

        var kdbx = KDBXReader(data)
        let xmlDocument = try kdbx.parse(unlockData: .init(masterPassword: masterPassword))
        let header = kdbx.header!

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

        print("")

        print("Block stream sizes: \(kdbx.blockSizes)")

        print("")

        let innerHeader = kdbx.innerHeader!
        print("Inner Header:")
        print("\tEncryption Algorithm: \(innerHeader.encryptionAlgorithm)")
        print("\tEncryption key: \(innerHeader.encryptionKey.hexString)")
        print("\tBinary Content: \(innerHeader.binaryContent.count) elements")
        for (index, element) in innerHeader.binaryContent.enumerated() {
            print("\t\t\(index): \(element.data.count) bytes" + (element.shouldBeProtected ? " [protected]" : ""))
        }

        print("")

        print(xmlDocument)
    }
}
