//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoSwift
import Foundation

/// The content of the `.kdbx` file.
public struct KDBXContent: Equatable {
    public var database: KDBX
    public let header: Header
    public let innerHeader: InnerHeader
}

extension KDBXContent {
    public enum DecryptError: Error {
        case corrupted(reason: String)
    }

    typealias GroupPath = [Int]

    struct EntryPath {
        let groupPath: GroupPath
        let entryIndex: Int
    }

    struct ProtectedStringPath: CustomDebugStringConvertible {
        let entryPath: EntryPath
        let historyIndex: Int?
        let stringIndex: Int

        var debugDescription: String {
            "ProtectedStringPath(groupPath: \(entryPath.groupPath), entryIndex: \(entryPath.entryIndex), historyIndex: \(historyIndex.map { String($0) } ?? "nil"), stringIndex: \(stringIndex))"
        }
    }

    public mutating func decrypt() throws(DecryptError) {
        var decryptor: ChaCha20

        switch innerHeader.encryptionAlgorithm {
        case .ChaCha20:
            guard let key = innerHeader.chaCha20Key else {
                // This should not be possible, we know it's a ChaCha20 so it must have correct
                // the encryption key of the right size. It must be a developer mistake putting
                // wrong key in the inner header.
                fatalError("Missing ChaCha20 key (encryptionion key \(innerHeader.encryptionKey.count) bytes)")
            }

            do {
                decryptor = try ChaCha20(key: key.key, iv: key.nonce)
            } catch {
                throw .corrupted(reason: "Failed to initialize ChaCha20 decryptor: \(error)")
            }

        case .Salsa20:
            fatalError("Salsa20 is not implemented yet")
        }

        func decrypt(data: [UInt8], at path: ProtectedStringPath, isLast: Bool) throws(DecryptError) -> String {
            let decryptedValue = Data(decryptor.decrypt(data))

            guard let stringValue = String(validating: decryptedValue, as: UTF8.self) else {
                // This is likely a developer mistake, something is wrong with our stream cipher.
                throw DecryptError.corrupted(reason: "Failed to create utf8 string from decrypted value at \(path)")
            }

            return stringValue
        }

        // Decrypt the protected strings from the XML document.
        // They are encrypted using a stream cipher so must be decrypted in order (breadth first).
        //
        // In addition the cipher needs to know if it's the last data block or not.
        //
        // So we store traverse the whole tree breadth first and store "previously visited node" here.
        // Then when encountering a new node, we decrypt the previous one, and save the "new last"
        // node.
        // And after we are done we decrypt the last node.
        var lastPath: ProtectedStringPath?
        var lastProtectedStringKey: String?
        var lastProtectedStringProtectedData: Data?

        do {
            try visitEntries(in: database.root.group) { entry, path throws(DecryptError) in
                for (stringIndex, protectedString) in entry.strings.enumerated() {
                    switch protectedString.value {
                    case let .protected(data):
                        if let lastPath, let lastProtectedStringKey, let lastProtectedStringProtectedData {
                            let unprotectedValue = try decrypt(data: Array(lastProtectedStringProtectedData), at: lastPath, isLast: false)
                            database.root.group.updateProtectedString(
                                to: .init(key: lastProtectedStringKey, value: .unprotected(unprotectedValue)),
                                groupPath: lastPath.entryPath.groupPath,
                                entryIndex: lastPath.entryPath.entryIndex,
                                historyIndex: lastPath.historyIndex,
                                stringIndex: lastPath.stringIndex
                            )
                        }

                        lastPath = .init(entryPath: path, historyIndex: nil, stringIndex: stringIndex)
                        lastProtectedStringKey = protectedString.key
                        lastProtectedStringProtectedData = data

                    case .regular, .unprotected, .protectedInMemory:
                        break
                    }
                }

                for (historyIndex, historicalEntry) in entry.history.enumerated() {
                    for (stringIndex, protectedString) in historicalEntry.strings.enumerated() {
                        switch protectedString.value {
                        case let .protected(data):
                            if let lastPath, let lastProtectedStringKey, let lastProtectedStringProtectedData {
                                let unprotectedValue = try decrypt(data: Array(lastProtectedStringProtectedData), at: lastPath, isLast: false)
                                database.root.group.updateProtectedString(
                                    to: .init(key: lastProtectedStringKey, value: .unprotected(unprotectedValue)),
                                    groupPath: lastPath.entryPath.groupPath,
                                    entryIndex: lastPath.entryPath.entryIndex,
                                    historyIndex: lastPath.historyIndex,
                                    stringIndex: lastPath.stringIndex
                                )
                            }

                            lastPath = .init(entryPath: path, historyIndex: historyIndex, stringIndex: stringIndex)
                            lastProtectedStringKey = protectedString.key
                            lastProtectedStringProtectedData = data

                        case .regular, .unprotected, .protectedInMemory:
                            break
                        }
                    }
                }
            }
        } catch let error as DecryptError {
            throw error
        } catch {
            // This should not be possible, only DecryptErrors are being thrown.
            // It's a limitation of Swift 6 typed throws, the type information gets lost
            // in the closure.
            // https://forums.swift.org/t/closure-property-that-throws-typed-error-in-swift-6-result-in-compiling-error/72433/5
            // https://forums.swift.org/t/closure-typed-throw/72730/4
            preconditionFailure("Unexpected error: \(error)")
        }

        // decrypt the last node.
        if let lastPath, let lastProtectedStringKey, let lastProtectedStringProtectedData {
            let unprotectedValue = try decrypt(data: Array(lastProtectedStringProtectedData), at: lastPath, isLast: true)
            database.root.group.updateProtectedString(
                to: .init(key: lastProtectedStringKey, value: .unprotected(unprotectedValue)),
                groupPath: lastPath.entryPath.groupPath,
                entryIndex: lastPath.entryPath.entryIndex,
                historyIndex: lastPath.historyIndex,
                stringIndex: lastPath.stringIndex
            )
        }
    }

    func visitEntries(
        in group: KDBX.Group,
        path groupPath: GroupPath = [],
        _ visitor: (KDBX.Entry, EntryPath) throws(DecryptError) -> Void
    ) rethrows {
        for (entryIndex, entry) in group.entries.enumerated() {
            try visitor(entry, .init(groupPath: groupPath, entryIndex: entryIndex))
        }

        for (groupIndex, group) in group.groups.enumerated() {
            try visitEntries(in: group, path: groupPath + [groupIndex], visitor)
        }
    }
}

extension KDBX.Group {
    mutating func updateProtectedString(
        to newValue: KDBX.ProtectedString,
        groupPath: [Int],
        entryIndex: Int,
        historyIndex: Int?,
        stringIndex: Int
    ) {
        if groupPath.isEmpty {
            assert(entryIndex < entries.count)
            assert(stringIndex < entries[entryIndex].strings.count)

            if let historyIndex {
                assert(historyIndex < entries[entryIndex].history.count)
                entries[entryIndex].history[historyIndex].strings[stringIndex] = newValue
            } else {
                entries[entryIndex].strings[stringIndex] = newValue
            }
            return
        }

        var groupPath = groupPath
        let groupIndex = groupPath.removeFirst()
        groups[groupIndex].updateProtectedString(
            to: newValue,
            groupPath: groupPath,
            entryIndex: entryIndex,
            historyIndex: historyIndex,
            stringIndex: stringIndex
        )
    }
}
