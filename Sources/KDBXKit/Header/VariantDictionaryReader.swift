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

    var cursor: ByteCursor

    init(data: Data) {
        cursor = ByteCursor(data)
    }

    // MARK: Read <token> helpers

    //
    // Bounds-checking lives in `ByteCursor`; these adapters only re-wrap its
    // `unexpectedEOF` into this reader's `Error`.

    private func readUInt8() throws(Error) -> UInt8 {
        do { return try cursor.readUInt8() } catch { throw .unexpectedEOF }
    }

    private func readUInt16() throws(Error) -> UInt16 {
        do { return try cursor.readUInt16LE() } catch { throw .unexpectedEOF }
    }

    private func readInt32() throws(Error) -> Int32 {
        do { return try cursor.readInt32LE() } catch { throw .unexpectedEOF }
    }

    private func readData(length: Int) throws(Error) -> Data {
        do { return try cursor.readData(length: length) } catch { throw .unexpectedEOF }
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
