//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.
/// 2. SHA-256 hash of the header.
/// 3. HMAC-SHA-256 hash of the header.
/// 4. In HMAC-protected block stream:
///    a. Encrypted:
///       i. Compressed (optional):
///          - Inner header.             <<- writes
///          - XML document.
/// ```
///
/// https://keepass.info/help/kb/kdbx.html#iheader
struct InnerHeaderWriter {
    enum Error: Swift.Error {
        case unknown(reason: String)
        /// When writing to a fixed length stream, there is no place to write.
        case unexpectedEOF
    }

    let outputStream: OutputStream

    init(to outputStream: OutputStream) {
        self.outputStream = outputStream
    }

    func write<T: FixedWidthInteger>(_ value: T) throws(Error) {
        try write(value.toDataLittleEndian())
    }

    func write(_ data: Data) throws(Error) {
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

    func writeField(_ type: InnerHeaderFieldType, value: Data) throws(Error) {
        // Inner header format is TLV content:
        // <ID type (UInt8)> || <Length (Int32)> || <Value>
        try write(type.rawValue)
        try write(Int32(value.count))
        try write(value)
    }

    func write(innerHeader: InnerHeader) throws(Error) {
        try writeField(.encryptionAlgorithm, value: innerHeader.encryptionAlgorithm.rawValue.toDataLittleEndian())
        try writeField(.encryptionKey, value: innerHeader.encryptionKey)

        for binaryContent in innerHeader.binaryContent {
            try write(InnerHeaderFieldType.binaryContent.rawValue)
            try write(Int32(binaryContent.data.count + 1))
            try write(UInt8(binaryContent.shouldBeProtected ? 0x01 : 0x00))
            try write(binaryContent.data)
        }

        try writeField(.endOfHeader, value: Data())
    }
}
