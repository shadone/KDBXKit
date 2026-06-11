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

    private func write(_ value: some FixedWidthInteger) throws(Error) {
        try write(value.toDataLittleEndian())
    }

    private func write(_ data: Data) throws(Error) {
        do {
            try outputStream.write(data: data)
        } catch {
            switch error {
            case let .streamError(error):
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

        // Emit keys in a stable order. A plain [String: …] iterates in a
        // hash-seed-dependent order that varies across processes, which
        // would make the KDF-parameter / publicCustomData header bytes
        // non-deterministic — the XML layer already sorts for the same
        // reason.
        for (key, value) in vardict.sorted(by: { $0.key < $1.key }) {
            let valueType: VariantDictionaryValueType
            let valueData: Data

            switch value {
            case let .uint32(value):
                valueType = .uint32
                valueData = value.toDataLittleEndian()

            case let .uint64(value):
                valueType = .uint64
                valueData = value.toDataLittleEndian()

            case let .boolean(b):
                valueType = .boolean
                let value: UInt8 = b ? 1 : 0
                valueData = value.toDataLittleEndian()

            case let .int32(value):
                valueType = .int32
                valueData = value.toDataLittleEndian()

            case let .int64(value):
                valueType = .int64
                valueData = value.toDataLittleEndian()

            case let .string(value):
                valueType = .string
                valueData = Data(value.utf8)

            case let .bytes(value):
                valueType = .bytes
                valueData = value
            }

            try writeField(valueType, name: key, value: valueData)
        }

        // Null terminator byte.
        try write(Data([0]))
    }
}
