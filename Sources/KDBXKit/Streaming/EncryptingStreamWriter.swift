//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

/// Streaming encryptor for the KDBX main payload. AES-256-CBC accumulates
/// incoming bytes, emits complete 16-byte ciphertext blocks during
/// `consume(_:)`, and appends a PKCS7-padded final block on `finalize()`.
/// ChaCha20 uses KDBXKit's stateful `ChaCha20` stream cipher (no padding,
/// every byte in produces one byte out immediately).
///
/// CBC implementation is over swift-crypto's single-block `AES.permute`
/// primitive — CBC mode itself (XOR with previous ciphertext, then
/// encrypt) is encoded inline. The block cipher remains the vetted
/// `AES.permute`; the mode glue is straightforward and matches the same
/// chain used by the eager `KDBXWriter` path.
final class EncryptingStreamWriter: StreamingByteConsumer {
    private enum Backend {
        case aesCBC(StreamingAESCBCEncryptor)
        case chacha20(ChaCha20)
    }

    private var backend: Backend
    private let downstream: any StreamingByteConsumer

    init(header: Header, mainKey: SecureBytes, downstream: any StreamingByteConsumer) throws {
        self.downstream = downstream
        switch header.encryptionAlgorithm {
        case .AES256CBC:
            let keyData = mainKey.withUnsafeBytes { keyPtr in
                Data(keyPtr.bindMemory(to: UInt8.self))
            }
            backend = .aesCBC(try StreamingAESCBCEncryptor(key: keyData, iv: header.encryptionNonce))
        case .ChaCha20:
            let cipher = try mainKey.withUnsafeBytes { keyPtr -> ChaCha20 in
                try ChaCha20(
                    key: Data(keyPtr.bindMemory(to: UInt8.self)),
                    iv: header.encryptionNonce
                )
            }
            backend = .chacha20(cipher)
        }
    }

    func consume(_ chunk: Data) throws {
        switch backend {
        case let .aesCBC(enc):
            let out = try enc.update(chunk)
            if !out.isEmpty {
                try downstream.consume(out)
            }
        case let .chacha20(cipher):
            if !chunk.isEmpty {
                let out = Data(cipher.encrypt(Array(chunk)))
                if !out.isEmpty {
                    try downstream.consume(out)
                }
            }
        }
    }

    func finalize() throws {
        switch backend {
        case let .aesCBC(enc):
            let tail = try enc.finalize()
            if !tail.isEmpty {
                try downstream.consume(tail)
            }
        case .chacha20:
            break
        }
        try downstream.finalize()
    }
}

/// PKCS7-padded streaming AES-256-CBC encryptor. Buffers up to 15 bytes
/// of un-encrypted input across `update` calls so partial blocks survive
/// chunk boundaries; on `finalize` appends a PKCS7 padding block (always
/// 1..16 bytes) and emits one final ciphertext block.
private final class StreamingAESCBCEncryptor {
    enum Error: Swift.Error, Sendable, Equatable {
        case invalidIVSize(Int)
        case invalidKeySize(Int)
        case cryptoFailure(String)
    }

    private let key: SymmetricKey
    private var previous: [UInt8] // last ciphertext block (16 bytes), IV initially
    private var buffer: [UInt8] = [] // un-encrypted residue, count in 0..<16

    init(key: Data, iv: Data) throws {
        guard iv.count == 16 else { throw Error.invalidIVSize(iv.count) }
        guard key.count == 32 else { throw Error.invalidKeySize(key.count) }
        self.key = SymmetricKey(data: key)
        previous = Array(iv)
    }

    func update(_ chunk: Data) throws -> Data {
        guard !chunk.isEmpty else { return Data() }
        buffer.append(contentsOf: chunk)

        // Emit all complete 16-byte blocks. Leave any residue (0..15 bytes)
        // in the buffer for the next call (or finalize).
        let fullBlockBytes = (buffer.count / 16) * 16
        guard fullBlockBytes > 0 else { return Data() }

        var out = Data()
        out.reserveCapacity(fullBlockBytes)
        var offset = 0
        while offset < fullBlockBytes {
            try emitBlock(plaintext: Array(buffer[offset..<offset + 16]), into: &out)
            offset += 16
        }
        buffer.removeFirst(fullBlockBytes)
        return out
    }

    func finalize() throws -> Data {
        // PKCS7: pad with (16 - residue) bytes of value (16 - residue).
        // When residue == 0, append a full block of 16 bytes of 0x10.
        let padLen = 16 - buffer.count
        buffer.append(contentsOf: Array(repeating: UInt8(padLen), count: padLen))

        precondition(buffer.count == 16, "PKCS7 padding produced an unexpected final block size")
        var out = Data()
        try emitBlock(plaintext: buffer, into: &out)
        buffer.removeAll()
        return out
    }

    private func emitBlock(plaintext: [UInt8], into out: inout Data) throws {
        var block = plaintext
        // C_i = E_K(P_i XOR C_{i-1})
        for i in 0..<16 {
            block[i] ^= previous[i]
        }
        do {
            try AES.permute(&block, key: key)
        } catch {
            throw Error.cryptoFailure(String(describing: error))
        }
        previous = block
        out.append(contentsOf: block)
    }
}
