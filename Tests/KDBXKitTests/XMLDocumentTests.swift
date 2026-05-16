//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

struct MockCryptor: Encryptable, Decryptable {
    func encrypt(_ input: any DataProtocol) -> any DataProtocol {
        input
    }

    func decrypt(_ input: any DataProtocol) -> any DataProtocol {
        input
    }
}

// A random date for convenience.
// XML document stores dates as number of full seconds since .NET epoch, so the dates we read
// should not have any sub-second precision so that date comparison in unit tests succeeds.
private let mockDate = Date(secondsSinceDotNetEpoch: 63_884_389_441)

let reference = KDBX(
    meta: .init(
        generator: "KDBXKit",
        headerHash: "FAdfQAm3M0qP06JqYWj1d2J+IB5GVDPDLY3jKHzsh1k=",
        settingsChanged: mockDate,
        databaseName: "Test Database",
        databaseNameChanged: mockDate,
        databaseDescription: "test database description",
        databaseDescriptionChanged: mockDate,
        defaultUserName: "hello",
        defaultUserNameChanged: mockDate,
        maintenanceHistoryDays: 123,
        color: .color(red: 12, green: 23, blue: 45),
        masterKeyChanged: mockDate,
        masterKeyChangeRec: .never,
        masterKeyChangeForce: .value(42),
        masterKeyChangeForceOnce: false,
        memoryProtection: .init(
            protectTitle: false,
            protectUserName: true,
            protectPassword: false,
            protectURL: true,
            protectNotes: false,
        ),
        customIcons: [
            .init(
                uuid: UUID(),
                data: Data([1, 2, 3]),
                name: "Test Icon",
                lastModificationTime: mockDate,
            ),
        ],
        recycleBinEnabled: true,
        recycleBinUUID: UUID(),
        recycleBinChanged: mockDate,
        entryTemplatesGroup: UUID(),
        entryTemplatesGroupChanged: mockDate,
        historyMaxSize: .value(123),
        lastSelectedGroup: UUID(),
        lastTopVisibleGroup: UUID(),
        customData: [
            .init(key: "Foo", value: "Bar"),
            .init(key: "Hello", value: "World", lastModificationTime: mockDate),
        ],
    ),
    root: .init(
        group: .init(
            uuid: UUID(),
            name: "Root Group",
            notes: "here goes notes",
            iconID: 123,
            customIconUUID: UUID(),
            times: .init(
                creationTime: mockDate,
                lastModificationTime: mockDate,
                lastAccessTime: mockDate,
                expiryTime: mockDate,
                expires: false,
                usageCount: 123_456,
                locationChanged: mockDate,
            ),
            isExpanded: true,
            defaultAutoTypeSequence: "foo",
            enableAutoType: .value(true),
            enableSearching: .null,
            lastTopVisibleEntry: UUID(),
            previousParentGroup: UUID(),
            tags: ["one", "two"],
            customData: [
                .init(key: "Hello", value: "World"),
            ],
            entries: [
                .init(
                    uuid: UUID(),
                    iconID: 42,
                    customIconUUID: UUID(),
                    foregroundColor: .color(red: 1, green: 2, blue: 3),
                    backgroundColor: .default,
                    overrideURL: "https://example.com",
                    qualityCheck: nil,
                    tags: ["a", "b"],
                    previousParentGroup: UUID(),
                    times: .init(
                        creationTime: mockDate,
                        lastModificationTime: mockDate,
                        lastAccessTime: mockDate,
                        expiryTime: mockDate,
                        expires: false,
                        usageCount: 123_456,
                        locationChanged: mockDate,
                    ),
                    strings: [
                        .init(key: "Title", value: .regular("Hello World")),
                        .init(key: "Password", value: .unprotected("god")),
                    ],
                    binaries: [
                        .init(key: "RefBinary", value: .ref(0)),
                        .init(key: "InlineBinary", value: .inline(Data([1, 2, 3]))),
                    ],
                    autoType: .init(
                        enabled: true,
                        dataTransferObfuscation: .twoChannelObfuscation,
                        defaultSequence: "blah",
                        association: [
                            .init(window: "a-window", keystrokeSequence: "alt+f4"),
                        ],
                    ),
                    customData: [
                        .init(key: "Foo", value: "Bar"),
                    ],
                    history: [
                        .init(
                            uuid: UUID(),
                            iconID: 42,
                            customIconUUID: UUID(),
                            foregroundColor: .color(red: 1, green: 2, blue: 3),
                            backgroundColor: .default,
                            overrideURL: "https://example.com",
                            qualityCheck: nil,
                            tags: ["a", "b"],
                            previousParentGroup: UUID(),
                            times: .init(
                                creationTime: mockDate,
                                lastModificationTime: mockDate,
                                lastAccessTime: mockDate,
                                expiryTime: mockDate,
                                expires: false,
                                usageCount: 123_456,
                                locationChanged: mockDate,
                            ),
                            strings: [
                                .init(key: "Title", value: .regular("Hello World")),
                                .init(key: "Password", value: .unprotected("god")),
                            ],
                            binaries: [],
                            autoType: .init(
                                enabled: true,
                                dataTransferObfuscation: .twoChannelObfuscation,
                                defaultSequence: "blah",
                                association: [
                                    .init(window: "a-window", keystrokeSequence: "alt+f4"),
                                ],
                            ),
                            customData: [
                                .init(key: "Foo", value: "Bar"),
                            ],
                        ),
                    ],
                ),
            ],
            groups: [
            ],
        ),
        deletedObjects: [],
    )
)

struct XMLDocumentTests {
    @Test
    func XMLDocumentReader_empty() async throws {
        let xmlFilepath = Bundle.module.path(forResource: "Resources/database-encrypted-empty", ofType: "xml")!
        let xmlDocument = try String(contentsOfFile: xmlFilepath, encoding: .utf8)

        // The fixture has no protected strings, so the keystream source's
        // key/nonce never actually run — a benign InnerHeader is enough.
        let reader = XMLDocumentReader(xmlDocument: xmlDocument, keystreamSource: Self.mockKeystream())
        let database = try reader.parse()

        #expect(database.meta.generator == "KeePassXC")
        #expect(database.meta.databaseName == "test3")
        #expect(database.meta.databaseNameChanged == Date(timeIntervalSince1970: 1_747_996_682))
        #expect(database.meta.maintenanceHistoryDays == 365)
    }

    // Note: a "write then read with MockCryptor (identity)" test used
    // to live here. After C-7's lazy refactor, the reader always
    // routes Protected="True" values through a real KeystreamSource,
    // and there's no useful identity stub — `writeThenReadWithInnerEncryption`
    // below exercises the same round-trip path with real ChaCha20.

    @Test
    func writeThenReadWithInnerEncryption() throws {
        let innerHeader = InnerHeader(
            encryptionAlgorithm: .ChaCha20,
            encryptionKey: Data(hexString: "584f97811553076c32b4ca004c19b77421280b5e596dd0f735c8d30e3063556c76b8cc3e63aed982e6fba693c6bbf21371db2c5e0d569e61e0655f59694093d8")!,
            binaryContent: []
        )

        let outputStream = OutputStream(toMemory: ())
        outputStream.open()
        let writer = XMLDocumentWriter(
            to: outputStream,
            encryptor: innerHeader.makeEncryptor()
        )
        try writer.write(reference)

        let data = outputStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        let xmlDocument = String(validating: data, as: UTF8.self)!

        let reader = XMLDocumentReader(
            xmlDocument: xmlDocument,
            keystreamSource: innerHeader.makeKeystreamSource()
        )
        let parsed = try reader.parse()

        #expect(parsed == reference)
    }

    /// Builds a no-op-equivalent `KeystreamSource` for fixtures that
    /// either have zero protected strings (so the source is never
    /// invoked) or were written with `MockCryptor` (identity cipher).
    /// In the second case, the test relies on the reader producing
    /// `.lazyInnerCipher` values that round-trip through `==` against
    /// the reference structure — `==` decrypts the lazy values, and
    /// since the writer didn't actually encrypt, the bytes match the
    /// reference plaintext.
    ///
    /// Caveat: this only works because `MockCryptor` is identity. If a
    /// future test mixes a real encrypting writer with this mock
    /// keystream, the reader will hand back gibberish — `==` will
    /// fail loudly, which is the right outcome.
    private static func mockKeystream() -> KeystreamSource {
        KeystreamSource(
            algorithm: .chacha20,
            key: SecureBytes(Data(repeating: 0, count: 32)),
            nonce: Data(repeating: 0, count: 12)
        )
    }
}
