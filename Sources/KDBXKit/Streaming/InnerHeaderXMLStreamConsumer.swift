//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// Terminal consumer of the decompressed inner stream for the streaming
/// metadata-only read. Walks the inner-header TLV records as bytes arrive,
/// **hashing and discarding** each binary-content payload (so attachment
/// bytes are never resident), captures the small cipher fields and
/// per-binary ``BinaryMetadata``, and accumulates only the trailing XML.
///
/// Upstream (``StreamingInflateReader``) delivers ≤64 KiB chunks, so the
/// `pending` work buffer stays ~64 KiB even while a multi-megabyte binary
/// streams through. Peak memory is therefore the XML size plus a small
/// window — independent of attachment size.
final class InnerHeaderXMLStreamConsumer: StreamingByteConsumer {
    // Inner-header field type bytes (mirror InnerHeaderFieldType).
    private static let endOfHeader: UInt8 = 0
    private static let encryptionAlgorithm: UInt8 = 1
    private static let encryptionKey: UInt8 = 2
    private static let binaryContent: UInt8 = 3

    /// Non-binary fields buffer whole before parsing, so their declared
    /// length needs a ceiling: legitimate fields are tiny (a 4-byte
    /// algorithm ID, a 64-byte key), and without a cap a crafted length
    /// grows `pending` unboundedly — defeating the memory bound this
    /// streaming path exists to provide.
    static let maxSmallFieldLength = 1 << 20

    private enum Phase { case header, xml }
    private var phase: Phase = .header

    /// Small work buffer for header-phase parsing. Never holds binary
    /// payloads beyond the current ≤64 KiB chunk.
    private var pending: [UInt8] = []
    /// High-water mark of `pending.count`. The streaming contract is that
    /// this stays a small window (≈ one upstream chunk) no matter how
    /// large the binary pool is — binaries drain straight through the
    /// hasher, never accumulating. A regression that buffered a whole
    /// binary would show up here as a peak that scales with attachment
    /// size; ``Tests/.../StreamingConsumerBufferTests`` pins the bound.
    private(set) var peakPendingBytes = 0
    /// Absolute offset into the decompressed stream of the next unparsed
    /// byte — used to stamp `BinaryMetadata.decompressedOffset`.
    private var absPos = 0

    // Captured header state.
    private var algorithm: InnerHeader.EncryptionAlgorithm?
    private var encryptionKeyData: Data?
    private(set) var binaries: [BinaryMetadata] = []

    // In-progress binary record.
    private var binaryRemaining = 0
    private var binaryLength = 0
    private var binaryOffset = 0
    private var binaryProtected = false
    private var binaryHasher = SHA256()

    /// Accumulated XML document bytes (the only large retained buffer).
    private(set) var xml = Data()

    private var finished = false

    func consume(_ chunk: Data) throws {
        guard !chunk.isEmpty else { return }
        if phase == .xml {
            xml.append(chunk)
            absPos += chunk.count
            return
        }
        pending.append(contentsOf: chunk)
        peakPendingBytes = max(peakPendingBytes, pending.count)
        try parseHeader()
    }

    func finalize() throws {
        guard phase == .xml else {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Inner header ended before the end-of-header marker")
        }
        finished = true
    }

    /// Parse as many complete inner-header records out of `pending` as
    /// possible, streaming binary payloads straight through the hasher.
    private func parseHeader() throws {
        while true {
            // Drain an in-progress binary payload first, never buffering it.
            if binaryRemaining > 0 {
                let take = min(binaryRemaining, pending.count)
                if take > 0 {
                    pending.withUnsafeBytes { binaryHasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0[0..<take])) }
                    pending.removeFirst(take)
                    binaryRemaining -= take
                    absPos += take
                }
                if binaryRemaining > 0 { return } // need more chunks
                finishBinary()
                continue
            }

            guard pending.count >= 5 else { return } // need type(1) + length(4)
            let type = pending[0]
            let length = Int(
                UInt32(pending[1])
                    | UInt32(pending[2]) << 8
                    | UInt32(pending[3]) << 16
                    | UInt32(pending[4]) << 24
            )

            if type == Self.binaryContent {
                // The value is flags(1) ‖ payload — a zero-length value has
                // no flags byte. The eager reader throws here too; consuming
                // anyway would eat one byte of the NEXT record as the flags
                // byte and desync all later parsing.
                guard length >= 1 else {
                    throw KDBXReader.Error.corruptedInnerHeader(reason: "Empty inner-header binaryContent field")
                }
                guard pending.count >= 6 else { return } // need the flags byte too
                let flags = pending[5]
                pending.removeFirst(6) // type + length + flags
                absPos += 6
                binaryProtected = (flags & 0x01) != 0
                binaryLength = length - 1 // value = flags(1) + payload
                binaryRemaining = binaryLength
                binaryOffset = absPos
                binaryHasher = SHA256()
                if binaryRemaining == 0 { finishBinary() }
                continue
            }

            // Small field: need the whole value buffered.
            guard length <= Self.maxSmallFieldLength else {
                throw KDBXReader.Error.corruptedInnerHeader(
                    reason: "Inner-header field of type \(type) declares an implausible length \(length)"
                )
            }
            let total = 5 + length
            guard pending.count >= total else { return }
            let value = Array(pending[5..<total])
            pending.removeFirst(total)
            absPos += total

            switch type {
            case Self.endOfHeader:
                phase = .xml
                if !pending.isEmpty {
                    xml.append(contentsOf: pending)
                    absPos += pending.count
                    pending.removeAll(keepingCapacity: false)
                }
                return
            case Self.encryptionAlgorithm:
                guard
                    let raw = Data(value).asInt32LE(),
                    let algo = InnerHeader.EncryptionAlgorithm(rawValue: raw)
                else {
                    throw KDBXReader.Error.corruptedInnerHeader(reason: "Invalid inner-stream encryption algorithm")
                }
                algorithm = algo
            case Self.encryptionKey:
                encryptionKeyData = Data(value)
            default:
                break // unknown field — skip (value already consumed)
            }
        }
    }

    private func finishBinary() {
        let digest = Data(binaryHasher.finalize())
        binaries.append(BinaryMetadata(
            sizeBytes: binaryLength,
            isProtected: binaryProtected,
            contentHash: digest,
            decompressedOffset: binaryOffset,
            decompressedLength: binaryLength
        ))
    }

    /// The parsed inner header (cipher params; empty binary content — the
    /// bytes were discarded), available after `finalize()`.
    func makeInnerHeader() throws -> InnerHeader {
        guard finished else {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Inner stream not finalized")
        }
        guard let algorithm else {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Missing inner-stream encryption algorithm")
        }
        guard let encryptionKeyData else {
            throw KDBXReader.Error.corruptedInnerHeader(reason: "Missing inner-stream encryption key")
        }
        return InnerHeader(
            encryptionAlgorithm: algorithm,
            encryptionKey: encryptionKeyData,
            binaryContent: []
        )
    }
}
