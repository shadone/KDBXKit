//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import CryptoSwift

/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.                           <<- writes
/// 2. SHA-256 hash of the header.
/// 3. HMAC-SHA-256 hash of the header.
/// 4. In HMAC-protected block stream:
///    a. Encrypted:
///       i. Compressed (optional):
///          - Inner header.
///          - XML document.
/// ```
///
/// https://keepass.info/help/kb/kdbx.html#iheader
struct HeaderWriter {
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

    private func writeField(_ type: HeaderFieldType, value: Data) throws(Error) {
        // Header format is TLV content:
        // <ID type (UInt8)> || <Length (Int32)> || <Value>
        try write(type.rawValue)
        try write(Int32(value.count))
        try write(value)
    }

    private func write(_ vardict: VariantDictionary) throws(Error) -> Data {
        do {
            let varDictOutputStream = OutputStream(toMemory: ())
            varDictOutputStream.open()
            try VariantDictionaryWriter(to: varDictOutputStream).write(vardict)
            guard let data = varDictOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
                fatalError("Failed to get output stream data for Public Custom Data")
            }
            return data
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case .unknown(let reason):
                throw .unknown(reason: "Failed to write Public Custom Data: \(reason)")
            }
        }
    }

    func write(_ header: Header) throws(Error) {
        guard outputStream.streamStatus == .open else {
            throw .unknown(reason: "Stream is not ready for writing")
        }

        try write(Header.signature1)
        try write(Header.signature2)
        try write(header.formatVersion.rawValue)
        try writeField(.encryptionAlgorithm, value: header.encryptionAlgorithm.rawValue.toDataLittleEndian())
        try writeField(.compressionAlgorithm, value: header.compressionAlgorithm.rawValue.toDataLittleEndian())
        try writeField(.masterSalt, value: header.masterSalt)
        try writeField(.encryptionNonce, value: header.encryptionNonce)
        try writeField(.kdfParameters, value: try write(header.kdfParameters.toVariantDictionary()))
        try writeField(.publicCustomData, value: try write(header.publicCustomData))
        try writeField(.endOfHeader, value: HeaderFieldType.endOfHeaderValue)
    }
}
