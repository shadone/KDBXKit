//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// https://keepass.info/help/kb/kdbx.html#vardict
class VariantDictionaryReader {
    enum Error: Swift.Error {
        case unsupportedFormatVersion(major: UInt8, minor: UInt8)

        case corrupted(reason: String)
        case unexpectedEOF
    }

    let data: Data
    var pos: Data.Index

    init(data: Data) {
        self.data = data
        pos = data.startIndex
    }

    // MARK: Read <token> helpers

    private func readUInt8() throws(Error) -> UInt8 {
        // `pos` is an absolute Data.Index (as `readData` below treats it).
        // Compare against endIndex, not count, and index `data` directly so
        // both helpers agree even for a non-zero-based slice.
        if pos.advanced(by: 1) > data.endIndex {
            throw Error.unexpectedEOF
        }

        let b = data[pos]

        pos = pos.advanced(by: 1)

        return b
    }

    private func readUInt16() throws(Error) -> UInt16 {
        try readData(length: 2).asUInt16LE()! // safe to force unwrap as we guaranteed to read enough bytes
    }

    private func readInt32() throws(Error) -> Int32 {
        try readData(length: 4).asInt32LE()! // safe to force unwrap as we guaranteed to read enough bytes
    }

    private func readData(length: Int) throws(Error) -> Data {
        // Reject a negative length (signed wire field with the high bit set)
        // before it builds a reversed `start..<end` Range and traps.
        if length < 0 {
            throw Error.unexpectedEOF
        }
        let start = pos
        let end = start.advanced(by: length)

        if end > data.endIndex {
            throw Error.unexpectedEOF
        }

        let subdata = data[start..<end]

        pos = end

        return subdata
    }

    // MARK: Public API

    func parse() throws(Error) -> VariantDictionary {
        // https://keepass.info/help/kb/kdbx.html#vardict

        // Format version, as UInt16
        let versionRawValue = try readUInt16()
        let formatVersion = VariantDictionary.FormatVersion(rawValue: versionRawValue)

        // The current version is 1.0, i.e. 0x0100.
        if formatVersion != .v1_0 {
            throw Error.unsupportedFormatVersion(major: formatVersion.major, minor: formatVersion.minor)
        }

        var result: VariantDictionary = [:]

        // Zero or more items: <Type (Byte)> || <Size of Name in bytes (Int32)> || <Name (String)> || <Size of Value in bytes <Int32> || <Value>
        while true {
            let type = try readUInt8()

            // Null terminator byte.
            if type == 0 {
                break
            }

            let nameLength = try readInt32()
            if nameLength <= 0 {
                throw Error.corrupted(reason: "Invalid name length \(nameLength) for type 0x\(String(format: "%02hhx", type))")
            }
            let nameData = try readData(length: Int(nameLength))
            guard let name = String(validating: nameData, as: UTF8.self) else {
                throw Error.corrupted(reason: "Invalid name data: \(nameData.hexString)")
            }

            let valueLength = try readInt32()
            if valueLength <= 0 {
                throw Error.corrupted(reason: "Invalid value length \(valueLength) for type 0x\(String(format: "%02hhx", type))")
            }
            let valueData = try readData(length: Int(valueLength))

            guard let valueType = VariantDictionaryValueType(rawValue: type) else {
                KDBXLog.header.debug("Unknown variant dictionary value type: \(type)")
                continue
            }

            switch valueType {
            case .uint32:
                guard
                    valueLength == 4,
                    let value = valueData.asUInt32LE()
                else {
                    throw Error.corrupted(reason: "Invalid variant dictionary value for uint32. Name='\(name)'; value=\(valueData.hexString)")
                }
                result[name] = .uint32(value)

            case .uint64:
                guard
                    valueLength == 8,
                    let value = valueData.asUInt64LE()
                else {
                    throw Error.corrupted(reason: "Invalid variant dictionary value for uint64. Name='\(name)'; value=\(valueData.hexString)")
                }
                result[name] = .uint64(value)

            case .boolean:
                guard valueLength == 1, let value = valueData.asBoolean() else {
                    throw Error.corrupted(reason: "Invalid variant dictionary value for boolean. Name='\(name)'; value=\(valueData.hexString)")
                }

                result[name] = .boolean(value)

            case .int32:
                guard
                    valueLength == 4,
                    let value = valueData.asInt32LE()
                else {
                    throw Error.corrupted(reason: "Invalid variant dictionary value for int32. Name='\(name)'; value=\(valueData.hexString)")
                }
                result[name] = .int32(value)

            case .int64:
                guard
                    valueLength == 8,
                    let value = valueData.asInt64LE()
                else {
                    throw Error.corrupted(reason: "Invalid variant dictionary value for int64. Name='\(name)'; value=\(valueData.hexString)")
                }
                result[name] = .int64(value)

            case .string:
                guard let value = String(validating: valueData, as: UTF8.self) else {
                    throw Error.corrupted(reason: "Invalid variant dictionary value for string. Name='\(name)'; value=\(valueData.hexString)")
                }
                result[name] = .string(value)

            case .bytes:
                result[name] = .bytes(valueData)
            }
        }

        return result
    }
}
