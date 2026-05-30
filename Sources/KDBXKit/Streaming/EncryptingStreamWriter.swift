//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#endif

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

#if canImport(CommonCrypto)
/// PKCS7-padded streaming AES-256-CBC encryptor over CommonCrypto, so the
/// per-block cipher runs on the CPU's AES instructions. The Swift
/// `AES.permute`-per-block fallback below encrypts at ~78 MB/s (one
/// swift-crypto call + a fresh array per 16-byte block); a `CCCryptor`
/// does the same payload at ~1 GB/s. `CCCryptorUpdate` buffers partial
/// blocks across chunk boundaries internally and `CCCryptorFinal` emits
/// the PKCS7 padding block, so this class just forwards bytes.
private final class StreamingAESCBCEncryptor {
    enum Error: Swift.Error, Sendable, Equatable {
        case invalidIVSize(Int)
        case invalidKeySize(Int)
        case cryptoFailure(String)
    }

    private let cryptor: CCCryptorRef

    init(key: Data, iv: Data) throws {
        guard iv.count == 16 else { throw Error.invalidIVSize(iv.count) }
        guard key.count == 32 else { throw Error.invalidKeySize(key.count) }
        var ref: CCCryptorRef?
        let status = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                CCCryptorCreate(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),
                    keyPtr.baseAddress, key.count,
                    ivPtr.baseAddress,
                    &ref
                )
            }
        }
        guard status == CCCryptorStatus(kCCSuccess), let ref else {
            throw Error.cryptoFailure("CCCryptorCreate failed with status \(status)")
        }
        cryptor = ref
    }

    deinit {
        CCCryptorRelease(cryptor)
    }

    func update(_ chunk: Data) throws -> Data {
        guard !chunk.isEmpty else { return Data() }
        let outCapacity = CCCryptorGetOutputLength(cryptor, chunk.count, false)
        return try run(input: chunk, outCapacity: outCapacity) { inPtr, outPtr, moved in
            CCCryptorUpdate(cryptor, inPtr, chunk.count, outPtr, outCapacity, &moved)
        }
    }

    func finalize() throws -> Data {
        let outCapacity = CCCryptorGetOutputLength(cryptor, 0, true)
        return try run(input: Data(), outCapacity: outCapacity) { _, outPtr, moved in
            CCCryptorFinal(cryptor, outPtr, outCapacity, &moved)
        }
    }

    /// Allocate an `outCapacity`-byte buffer, run `body` (an Update or
    /// Final call) over `input`, and trim to the bytes actually written.
    /// `body` is invoked even when `outCapacity` is 0 — a partial-block
    /// `update` produces no ciphertext yet but must still feed
    /// `CCCryptorUpdate` so the bytes are buffered for the next call.
    private func run(
        input: Data,
        outCapacity: Int,
        _ body: (_ inPtr: UnsafeRawPointer?, _ outPtr: UnsafeMutableRawPointer?, _ moved: inout Int) -> CCCryptorStatus
    ) throws -> Data {
        var output = Data(count: outCapacity)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outPtr in
            input.withUnsafeBytes { inPtr in
                body(inPtr.baseAddress, outPtr.baseAddress, &moved)
            }
        }
        guard status == CCCryptorStatus(kCCSuccess) else {
            throw Error.cryptoFailure("CCCryptor failed with status \(status)")
        }
        if moved < output.count {
            output.removeSubrange(moved..<output.count)
        }
        return output
    }
}
#else
/// PKCS7-padded streaming AES-256-CBC encryptor. Buffers up to 15 bytes
/// of un-encrypted input across `update` calls so partial blocks survive
/// chunk boundaries; on `finalize` appends a PKCS7 padding block (always
/// 1..16 bytes) and emits one final ciphertext block.
///
/// swift-crypto fallback for non-Apple platforms (Linux/CI). CBC mode is
/// encoded inline over the vetted single-block `AES.permute`; Apple builds
/// use the CommonCrypto variant above for hardware AES.
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
#endif
