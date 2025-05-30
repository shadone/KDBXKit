//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// https://keepass.info/help/kb/kdbx.html#vardict
struct VariantDictionaryWriter {
    enum Error: Swift.Error {
        case unknown(reason: String)
        /// When writing to a fixed length stream, there is no place to write.
        case unexpectedEOF
    }

    let outputStream: OutputStream

    init(to outputStream: OutputStream) {
        self.outputStream = outputStream
    }

    private func write<T: FixedWidthInteger>(_ value: T) throws(Error) {
        try write(value.toDataLittleEndian())
    }

    private func write(_ data: Data) throws(Error) {
        do {
            try outputStream.write(data: data)
        } catch {
            switch error {
            case .streamError(let error):
                let description = error?.localizedDescription ?? "nil"
                throw .unknown(reason: "Write failed: \(description)")

            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }
    }

    private func writeField(_ type: VariantDictionaryValueType, name: String, value: Data) throws(Error) {
        // <Type (Byte)> || <Size of Name in bytes (Int32)> || <Name (String)> || <Size of Value in bytes <Int32> || <Value>
        try write(type.rawValue)
        let nameData = Data(name.utf8)
        try write(Int32(nameData.count))
        try write(nameData)
        try write(Int32(value.count))
        try write(value)
    }

    func write(_ vardict: VariantDictionary) throws(Error) {
        guard outputStream.streamStatus == .open else {
            throw .unknown(reason: "Stream is not ready for writing")
        }

        try write(VariantDictionary.FormatVersion.v1_0.rawValue.toDataLittleEndian())

        for (key, value) in vardict {
            let valueType: VariantDictionaryValueType
            let valueData: Data

            switch value {
            case .uint32(let value):
                valueType = .uint32
                valueData = value.toDataLittleEndian()

            case .uint64(let value):
                valueType = .uint64
                valueData = value.toDataLittleEndian()

            case .boolean(let b):
                valueType = .boolean
                let value: UInt8 = b ? 1 : 0
                valueData = value.toDataLittleEndian()

            case .int32(let value):
                valueType = .int32
                valueData = value.toDataLittleEndian()

            case .int64(let value):
                valueType = .int64
                valueData = value.toDataLittleEndian()

            case .string(let value):
                valueType = .string
                valueData = Data(value.utf8)

            case .bytes(let value):
                valueType = .bytes
                valueData = value
            }

            try writeField(valueType, name: key, value: valueData)
        }

        // Null terminator byte.
        try write(Data([0]))
    }
}
