//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Crypto
import Foundation

/// Streaming writer for the KDBX HMAC-protected block format. Each
/// incoming byte gets buffered until we have a full 1 MB block (or
/// `finalize()` is called with a partial buffer), then we emit
/// `HMAC(32) | size(4) | block` to the underlying `FileHandle`.
/// `finalize()` also writes the terminator block (size = 0) that
/// signals end-of-stream to the reader.
final class HMACBlockStreamWriter: StreamingByteConsumer {
    /// 1 MB matches KeePass's choice.
    private static let blockSize = 1_048_576

    private let fileHandle: FileHandle
    private let masterSalt: Data
    private let unlockKey: SecureBytes

    private var buffer: Data = .init(capacity: HMACBlockStreamWriter.blockSize)
    private var blockIndex: UInt64 = 0

    init(fileHandle: FileHandle, masterSalt: Data, unlockKey: SecureBytes) {
        self.fileHandle = fileHandle
        self.masterSalt = masterSalt
        self.unlockKey = unlockKey
    }

    func consume(_ chunk: Data) throws {
        buffer.append(chunk)
        while buffer.count >= Self.blockSize {
            let block = buffer.prefix(Self.blockSize)
            try writeBlock(Data(block))
            buffer.removeFirst(Self.blockSize)
        }
    }

    func finalize() throws {
        if !buffer.isEmpty {
            try writeBlock(buffer)
            buffer = Data()
        }
        // Terminator: empty block signals end of stream.
        try writeBlock(Data())
    }

    private func writeBlock(_ block: Data) throws {
        let blockKey = HMACProtectedBlockStream.keyForBlock(
            at: blockIndex,
            masterSalt: masterSalt,
            unlockKey: unlockKey
        )
        let blockSize = Int32(block.count)
        var digest = HMAC<SHA256>(key: SymmetricKey(data: blockKey))
        digest.update(data: blockIndex.dataLE)
        digest.update(data: blockSize.dataLE)
        digest.update(data: block)
        let hmac = Data(digest.finalize())

        try fileHandle.write(contentsOf: hmac)
        try fileHandle.write(contentsOf: blockSize.dataLE)
        if !block.isEmpty {
            try fileHandle.write(contentsOf: block)
        }
        blockIndex += 1
    }
}
