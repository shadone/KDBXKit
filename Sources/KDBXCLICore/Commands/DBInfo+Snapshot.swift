//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import KDBXKit

/// Snapshot of everything `db info` prints. Built once from the reader, then
/// emitted either as line-oriented text or as a JSON document.
struct DBInfoSnapshot: Encodable {
    enum UnlockState: String, Encodable {
        case notAttempted
        case unlocked
        case wrongCredentials
    }

    let header: Header
    let unlockState: UnlockState
    let blockSizes: [Int32]
    let innerHeader: InnerHeader?
    let validationIssues: [ValidationFailure]

    // MARK: - JSON

    private enum CodingKeys: String, CodingKey {
        case header
        case unlockState
        case blockSizes
        case innerHeader
        case validationIssues
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(HeaderDTO(header), forKey: .header)
        try c.encode(unlockState, forKey: .unlockState)
        try c.encode(blockSizes, forKey: .blockSizes)
        try c.encodeIfPresent(innerHeader.map(InnerHeaderDTO.init), forKey: .innerHeader)
        try c.encode(validationIssues.map(ValidationIssueDTO.init), forKey: .validationIssues)
    }

    // MARK: - Human

    func printHuman() {
        print("Format version: \(header.formatVersion)")
        if header.formatVersion.isLegacy3x {
            // Pre-KDBX-4 file. The writer always emits 4.1, so any
            // mutation that touches `db rekey` / `entry set` / etc.
            // will silently upgrade the on-disk format. Surfacing the
            // notice from `db info` lets users see the upgrade
            // pending before they trigger it.
            print("Legacy format: saving will upgrade to KDBX 4.1.")
            print("              Run `kdbx db migrate` to upgrade explicitly.")
        }
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

        if unlockState == .wrongCredentials {
            print("")
            print("Error: The specified master password is not correct.")
        }

        if !blockSizes.isEmpty {
            print("")
            print("Block stream sizes: \(blockSizes)")
        }

        if let innerHeader {
            print("")
            print("Inner Header:")
            print("\tEncryption Algorithm: \(innerHeader.encryptionAlgorithm)")
            // The inner-stream key is never printed: it decrypts every
            // Protected="True" field, and `db xml` output leaves those
            // values inner-cipher-encrypted — together a scrollback
            // capture would allow offline decryption of all of them.
            print("\tBinary Content: \(innerHeader.binaryContent.count) elements")
            for (index, element) in innerHeader.binaryContent.enumerated() {
                print("\t\t\(index): \(element.data.count) bytes" + (element.shouldBeProtected ? " [protected]" : ""))
            }
        }

        if !validationIssues.isEmpty {
            print("")
            print("Validation issues:")
            for issue in validationIssues {
                print("\t \(issue.level.description): \(issue.message)")
            }
        }
    }
}

// MARK: - JSON DTOs

private struct HeaderDTO: Encodable {
    let formatVersion: String
    let legacyFormatNotice: String?
    let encryptionAlgorithm: String
    let compressionAlgorithm: String
    let masterSalt: String
    let encryptionNonce: String
    let kdf: KDFDTO
    let publicCustomData: [String: String]

    init(_ header: Header) {
        formatVersion = "\(header.formatVersion.major).\(header.formatVersion.minor)"
        // Mirrors `KDBXContent.legacyFormatNotice` for callers that
        // parse `db info --output json`. Encoded as a short string
        // (rather than a structured object) because the JSON
        // consumer's job here is to display, not to dispatch.
        legacyFormatNotice = header.formatVersion.isLegacy3x
            ? "Saving will upgrade KDBX \(header.formatVersion) to 4.1."
            : nil
        encryptionAlgorithm = "\(header.encryptionAlgorithm)"
        compressionAlgorithm = header.compressionAlgorithm.description
        masterSalt = header.masterSalt.hexString
        encryptionNonce = header.encryptionNonce.hexString
        kdf = KDFDTO(header.kdfParameters)
        // VariantDictionary holds typed scalars; stringify for JSON portability.
        var dict: [String: String] = [:]
        for (k, v) in header.publicCustomData {
            dict[k] = "\(v)"
        }
        publicCustomData = dict
    }
}

private struct KDFDTO: Encodable {
    let type: String
    let salt: String
    let rounds: UInt64?
    let argon2Version: String?
    let memoryKiB: UInt64?
    let parallelism: UInt32?
    let iterations: UInt64?
    let uuid: String?

    init(_ params: KDFParameters) {
        switch params {
        case let .aes(aes, _):
            type = "aes-kdf"
            salt = aes.salt.hexString
            rounds = aes.rounds
            argon2Version = nil
            memoryKiB = nil
            parallelism = nil
            iterations = nil
            uuid = nil

        case let .argon2d(p, _):
            type = "argon2d"
            salt = p.salt.hexString
            rounds = nil
            argon2Version = p.version.description
            memoryKiB = p.memory / 1024
            parallelism = p.parallelism
            iterations = p.iterations
            uuid = nil

        case let .argon2id(p, _):
            type = "argon2id"
            salt = p.salt.hexString
            rounds = nil
            argon2Version = p.version.description
            memoryKiB = p.memory / 1024
            parallelism = p.parallelism
            iterations = p.iterations
            uuid = nil

        case let .unknown(id):
            type = "unknown"
            salt = ""
            rounds = nil
            argon2Version = nil
            memoryKiB = nil
            parallelism = nil
            iterations = nil
            uuid = id.uuidString
        }
    }
}

private struct InnerHeaderDTO: Encodable {
    struct BinaryDTO: Encodable {
        let index: Int
        let size: Int
        let protected: Bool
    }

    let encryptionAlgorithm: String
    let binaries: [BinaryDTO]

    init(_ ih: InnerHeader) {
        encryptionAlgorithm = "\(ih.encryptionAlgorithm)"
        binaries = ih.binaryContent.enumerated().map { idx, b in
            BinaryDTO(index: idx, size: b.data.count, protected: b.shouldBeProtected)
        }
    }
}

private struct ValidationIssueDTO: Encodable {
    let level: String
    let message: String

    init(_ issue: ValidationFailure) {
        level = "\(issue.level)".lowercased()
        message = issue.message
    }
}
