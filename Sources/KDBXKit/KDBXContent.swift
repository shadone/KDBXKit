//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoSwift
import Foundation

/// The content of the `.kdbx` file.
public struct KDBXContent: Equatable {
    public var database: Database
    public let header: Header
    public let innerHeader: InnerHeader
}

extension KDBXContent {
    public enum DecryptError: Error {
        case corrupted(reason: String)
    }

    struct ValuePath {
        let entryIndex: Int
        let stringIndex: Int
    }

    public mutating func decrypt() throws(DecryptError) {
        var decryptor: Cryptor & Updatable

        switch innerHeader.encryptionAlgorithm {
        case .ChaCha20:
            guard let key = innerHeader.chaCha20Key else {
                fatalError("Missing ChaCha20 key")
            }

            do {
                let chacha20 = try ChaCha20(key: key.key, iv: key.nonce)
                decryptor = chacha20.makeDecryptor()
            } catch {
                print("###", error)
                return
            }

        case .Salsa20:
            fatalError("Salsa20 is not implemented yet")
        }

        func decrypt(data: [UInt8], at path: ValuePath, isLast: Bool) throws(DecryptError) {
            let decryptedValue: Data
            do {
                let bytes = try decryptor.update(withBytes: data, isLast: isLast)
                decryptedValue = Data(bytes)
            } catch {
                throw .corrupted(reason: "Failed to decrypt value at \(path): \(error)")
            }

            guard let stringValue = String(data: decryptedValue, encoding: .utf8) else {
                throw DecryptError.corrupted(reason: "Failed to create utf8 string from decrypted value at \(path)")
            }

            unprotectString(stringValue, at: path)
        }

        var lastPath: ValuePath?
        var lastEncryptedValue: Data?

        for entryIndex in 0..<database.root.group.entries.count {
            let entry = database.root.group.entries[entryIndex]
            for stringIndex in 0..<entry.strings.count {
                switch entry.strings[stringIndex].value {
                case .protected(let data):
                    if let lastPath, let lastEncryptedValue {
                        try decrypt(data: Array(lastEncryptedValue), at: lastPath, isLast: false)
                    }

                    lastPath = .init(entryIndex: entryIndex, stringIndex: stringIndex)
                    lastEncryptedValue = data

                case .regular, .unprotected, .protectedInMemory:
                    break
                }
            }
        }

        if let lastPath, let lastEncryptedValue {
            try decrypt(data: Array(lastEncryptedValue), at: lastPath, isLast: true)
        }
    }

    private mutating func unprotectString(
        _ unprotectedValue: String,
        at path: ValuePath
    ) {
        database.root.group.entries[path.entryIndex].strings[path.stringIndex].value = .unprotected(unprotectedValue)
    }
}
