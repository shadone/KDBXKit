//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
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
///          - Inner header.             <<- parses & returns binary content
///          - XML document.
/// ```
///
/// https://keepass.info/help/kb/kdbx.html#iheader
struct InnerHeaderReader {
    enum Error: Swift.Error {
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

    private mutating func readUInt8() throws(Error) -> UInt8 {
        do { return try cursor.readUInt8() } catch { throw .unexpectedEOF }
    }

    private mutating func readInt32() throws(Error) -> Int32 {
        do { return try cursor.readInt32LE() } catch { throw .unexpectedEOF }
    }

    private mutating func readData(length: Int) throws(Error) -> Data {
        do { return try cursor.readData(length: length) } catch { throw .unexpectedEOF }
    }

    // MARK: Public API

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

            guard let fieldType = InnerHeaderFieldType(rawValue: type) else {
                KDBXLog.innerHeader.debug("Unknown inner header field type: \(type)")
                continue
            }

            switch fieldType {
            case .endOfHeader:
                done = true

            case .encryptionAlgorithm:
                guard
                    let algorithmValue = valueData.asInt32LE(),
                    let algorithm = InnerHeader.EncryptionAlgorithm(rawValue: algorithmValue)
                else {
                    throw Error.corrupted(reason: "Invalid inner header encryption algorithm. bytes: \(valueData.hexString)")
                }
                encryptionAlgorithm = algorithm

            case .encryptionKey:
                encryptionKey = valueData

            case .binaryContent:
                // A binaryContent value is f ‖ C — at minimum the 1-byte
                // flags. A zero-length value has no flags byte; reject it
                // instead of trapping on the empty subscript.
                guard let flags = valueData.first else {
                    throw Error.corrupted(reason: "Empty inner-header binaryContent field")
                }
                let binaryData: Data
                if valueData.count > 1 {
                    let start = valueData.startIndex + 1
                    let end = valueData.endIndex
                    binaryData = valueData.subdata(in: start..<end)
                } else {
                    binaryData = Data()
                }
                binaryContent.append(.init(shouldBeProtected: (flags & 0x01) != 0, data: binaryData))
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

        return (header: header, length: cursor.position)
    }

    /// Metadata-only variant of `parse()`. Walks the inner header the
    /// same way but for each binary captures `(offset, length, hash,
    /// protected)` into `BinaryMetadata` instead of holding the bytes
    /// on the returned `InnerHeader.binaryContent`. The returned
    /// `InnerHeader` has `binaryContent: []` by construction.
    ///
    /// Offsets are relative to the start of the decompressed
    /// inner-header buffer that this reader was initialized with — so
    /// `streamBinary` can reopen the source, replay decrypt +
    /// decompress, seek to `decompressedOffset`, and read
    /// `decompressedLength` bytes.
    mutating func parseMetadata() throws(Error) -> (header: InnerHeader, binaries: [BinaryMetadata], length: Int) {
        var encryptionAlgorithm: InnerHeader.EncryptionAlgorithm?
        var encryptionKey: Data?
        var binaries: [BinaryMetadata] = []

        var done = false
        while !done {
            // Capture the offset of the *value* bytes before reading
            // them — we'll need this to locate the binary payload
            // within the decompressed stream. The TLV is:
            //   type (1) | length (4) | value (length)
            // For binary content, value is: flags (1) | bytes (length - 1).
            // So the binary bytes start at (pos_after_length_read + 1)
            // i.e. valueStart + 1 relative to the buffer.
            let type = try readUInt8()
            let valueLength = try readInt32()
            let valueStart = cursor.position // index into the buffer where value bytes begin
            let valueData = try readData(length: Int(valueLength))

            guard let fieldType = InnerHeaderFieldType(rawValue: type) else {
                KDBXLog.innerHeader.debug("Unknown inner header field type: \(type)")
                continue
            }

            switch fieldType {
            case .endOfHeader:
                done = true

            case .encryptionAlgorithm:
                guard
                    let algorithmValue = valueData.asInt32LE(),
                    let algorithm = InnerHeader.EncryptionAlgorithm(rawValue: algorithmValue)
                else {
                    throw Error.corrupted(reason: "Invalid inner header encryption algorithm. bytes: \(valueData.hexString)")
                }
                encryptionAlgorithm = algorithm

            case .encryptionKey:
                encryptionKey = valueData

            case .binaryContent:
                // See `parse()`: a zero-length binaryContent has no flags
                // byte; reject rather than trap on the empty subscript.
                guard let flags = valueData.first else {
                    throw Error.corrupted(reason: "Empty inner-header binaryContent field")
                }
                let isProtected = (flags & 0x01) != 0
                let binaryBytesOffset = valueStart + 1 // skip flags byte
                let binaryBytesLength = max(0, Int(valueLength) - 1)
                // The payload is `valueData` minus its leading flags byte —
                // slice it directly rather than re-indexing the backing
                // buffer (which assumed a zero-based `data`).
                let binaryBytes: Data = binaryBytesLength > 0
                    ? valueData.subdata(in: valueData.startIndex + 1..<valueData.endIndex)
                    : Data()
                let hash = Data(SHA256.hash(data: binaryBytes))
                binaries.append(.init(
                    sizeBytes: binaryBytesLength,
                    isProtected: isProtected,
                    contentHash: hash,
                    decompressedOffset: binaryBytesOffset,
                    decompressedLength: binaryBytesLength
                ))
            }
        }

        guard let encryptionAlgorithm else {
            throw Error.corrupted(reason: "Missing encryption algorithm")
        }
        guard let encryptionKey else {
            throw Error.corrupted(reason: "Missing encryption key")
        }

        // Build an InnerHeader with the cipher parameters but no
        // binary payloads. Callers that need byte access go through
        // the lazy stream path.
        let header = InnerHeader(
            encryptionAlgorithm: encryptionAlgorithm,
            encryptionKey: encryptionKey,
            binaryContent: []
        )

        return (header: header, binaries: binaries, length: cursor.position)
    }
}
