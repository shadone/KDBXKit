//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

struct InnerHeaderReader {
    enum Error: Swift.Error {
        case corrupted(reason: String)
        case unexpectedEOF
    }

    let data: Data
    var pos: Data.Index

    init(data: Data) {
        self.data = data
        pos = data.startIndex
    }

    private mutating func readUInt8() throws(Error) -> UInt8 {
        if pos + 1 > data.count {
            throw Error.unexpectedEOF
        }

        let b = data[pos]

        pos = pos.advanced(by: 1)

        return b
    }

    private mutating func readInt32() throws(Error) -> Int32 {
        try readData(length: 4).asInt32LE()! // safe to force unwrap as we guaranteed to read enough bytes
    }

    private mutating func readData(length: Int) throws(Error) -> Data {
        let start = pos
        let end = pos.advanced(by: length)

        if end > data.endIndex {
            throw Error.unexpectedEOF
        }

        let subdata = data.subdata(in: start..<end)

        pos = end

        return subdata
    }

    mutating func parse() throws(Error) -> (header: InnerHeader, length: Int) {
        var encryptionAlgorithm: InnerHeader.EncryptionAlgorithm?
        var encryptionKey: Data?
        var binaryContent: [InnerHeader.BinaryContent] = []

        // An inner header field consists of an ID t (byte) and a value V (type depends on t).
        // Let s be the size of V in bytes, as Int32. Each header field is stored as follows:
        // t ‖ s ‖ V.
        var done = false
        while !done {
            // parse fields: <ID type (UInt8)> || <Length (Int32)> || <Value>
            let type = try readUInt8()
            let valueLength = try readInt32()
            let valueData = try readData(length: Int(valueLength))

            print("Got inner header field: type=\(type), length=\(valueLength); value[<10]=\(valueData.prefix(10).hexString)")

            guard let fieldType = InnerHeaderFieldType(rawValue: type) else {
                print("Unknown inner header field type: \(type)")
                continue
            }

            switch fieldType {
            case .endOfHeader:
                done = true

            case .encryptionAlgorithm:
                let algorithm = valueData.asInt32LE()
                if algorithm == 2 {
                    encryptionAlgorithm = .Salsa20
                } else if algorithm == 3 {
                    encryptionAlgorithm = .ChaCha20
                } else {
                    throw Error.corrupted(reason: "Invalid inner header encryption algorithm. bytes: \(valueData.hexString)")
                }

            case .encryptionKey:
                encryptionKey = valueData

            case .binaryContent:
                let flags = valueData[valueData.startIndex]
                let start = valueData.startIndex
                let end = valueData.endIndex
                let binaryData = valueData.subdata(in: start..<end)
                binaryContent.append(.init(shouldBeProtected: flags == 0x01, data: binaryData))
            }
        }

        // Parsing done, validate parsed data

        guard let encryptionAlgorithm else {
            throw Error.corrupted(reason: "Missing encryption algorithm")
        }
        guard let encryptionKey else {
            throw Error.corrupted(reason: "Missing encryption key")
        }

        // 🎉

        let header = InnerHeader(
            encryptionAlgorithm: encryptionAlgorithm,
            encryptionKey: encryptionKey,
            binaryContent: binaryContent
        )

        return (header: header, length: pos)
    }
}
