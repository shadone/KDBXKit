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

    private func writeField(_ type: HeaderFieldType, value: Data) throws(Error) {
        // Header format is TLV content:
        // <ID type (UInt8)> || <Length (Int32)> || <Value>
        try write(type.rawValue)
        try write(Int32(value.count))
        try write(value)
    }

    private func write(_ vardict: VariantDictionary) throws(Error) -> Data {
        let varDictOutputStream = OutputStream(toMemory: ())
        varDictOutputStream.open()
        do {
            try VariantDictionaryWriter(to: varDictOutputStream).write(vardict)
        } catch {
            switch error {
            case .unexpectedEOF:
                throw .unexpectedEOF
            case let .unknown(reason):
                throw .unknown(reason: "Failed to write Variant Dictionary: \(reason)")
            }
        }
        guard let data = varDictOutputStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            // Foundation invariant: an OutputStream(toMemory:) always exposes
            // its written bytes via this property. Throw rather than trap — a
            // Foundation behavior change shouldn't take the whole process down
            // mid-save.
            throw .unknown(reason: "OutputStream(toMemory:) exposed no data for Variant Dictionary")
        }
        return data
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
        try writeField(.kdfParameters, value: write(header.kdfParameters.toVariantDictionary()))
        // KeePass omits the PublicCustomData field entirely when empty;
        // the reader defaults a missing field to [:], so this round-trips.
        if !header.publicCustomData.isEmpty {
            try writeField(.publicCustomData, value: write(header.publicCustomData))
        }
        try writeField(.endOfHeader, value: HeaderFieldType.endOfHeaderValue)
    }
}
