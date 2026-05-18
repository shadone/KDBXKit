//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Reader for the KDBX 3.x hashed-block stream.
///
/// The 3.x analog of ``HMACProtectedBlockStream``: integrity is established
/// per-block by a SHA-256 digest of the block's payload bytes (KDBX 4
/// switched to an HMAC keyed by the unlock key + block index so the digest
/// also authenticates the credentials).
///
/// On-the-wire layout (little endian) repeated until a zero-length sentinel:
///
/// ```
/// UInt32 blockId
/// Byte[32] blockHash       SHA-256(blockData)
/// UInt32 blockSize
/// Byte[blockSize] blockData
/// ```
///
/// A `blockSize == 0` block marks end-of-stream. KeePass's writer emits an
/// all-zero `blockHash` in that sentinel; we don't check it (any 32 bytes
/// are accepted) because the hash has nothing to authenticate.
enum HashedBlockStreamReader {
    enum Error: Swift.Error, Equatable {
        /// A block's payload digest did not match the stored SHA-256.
        /// Suggests on-disk corruption or truncation. Unlike the 4.x HMAC
        /// check, a mismatch here is not credential-related — the AES-CBC
        /// decrypt would have produced garbage long before we got here,
        /// and that garbage's hash won't equal the stored one.
        case blockHashMismatch(blockIndex: UInt32)
        /// Stream ended before a zero-length terminator was reached.
        case unterminatedStream
        case unexpectedEOF
    }

    /// Decode the hashed block stream contained in `data` (starting at
    /// `data.startIndex`) into a single contiguous `Data`.
    ///
    /// `data` must contain exactly the hashed stream — anything before or
    /// after is treated as corruption. In the KDBX 3.x read path this is
    /// satisfied because the AES-CBC plaintext (minus the leading 32-byte
    /// `StreamStartBytes` already stripped by the caller) is exactly the
    /// hashed stream.
    static func decode(_ data: Data) throws(Error) -> Data {
        var pos = data.startIndex
        var payload = Data(capacity: data.count)

        while true {
            guard pos.advanced(by: 4 + 32 + 4) <= data.endIndex else {
                throw .unexpectedEOF
            }

            // blockId — present for ordering but not used by the reader.
            // KeePass writes a monotonically increasing index; some
            // ill-behaved producers don't, so we just consume it.
            let blockIdData = data.subdata(in: pos..<pos.advanced(by: 4))
            pos = pos.advanced(by: 4)
            guard let blockId = blockIdData.asUInt32LE() else {
                throw .unexpectedEOF
            }

            let storedHash = data.subdata(in: pos..<pos.advanced(by: 32))
            pos = pos.advanced(by: 32)

            let sizeData = data.subdata(in: pos..<pos.advanced(by: 4))
            pos = pos.advanced(by: 4)
            guard let size = sizeData.asUInt32LE() else {
                throw .unexpectedEOF
            }

            if size == 0 {
                // Terminator: the stored hash is conventionally 32 zero bytes,
                // but we don't enforce that — it would just create churn for
                // future writers that pick a different convention. There's
                // nothing to authenticate either way.
                _ = storedHash
                return payload
            }

            let blockEnd = pos.advanced(by: Int(size))
            guard blockEnd <= data.endIndex else {
                throw .unexpectedEOF
            }
            let block = data.subdata(in: pos..<blockEnd)
            pos = blockEnd

            let computedHash = block.sha256()
            if !ConstantTime.equals(computedHash, storedHash) {
                throw .blockHashMismatch(blockIndex: blockId)
            }

            payload.append(block)
        }
    }
}
