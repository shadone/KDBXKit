//
// Copyright (c) 2026, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import _CryptoExtras
import Crypto
import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// Streaming decryptor for the KDBX main payload — the read-side mirror of
/// ``EncryptingStreamWriter``. Callers push ciphertext chunks (one
/// HMAC-verified block at a time) via ``consume(_:)``; it decrypts
/// incrementally and forwards plaintext (still gzip-compressed) downstream.
///
/// ChaCha20 reuses KDBXKit's stateful ``ChaCha20`` (the keystream position
/// carries across calls, byte-for-byte). AES-256-CBC uses CommonCrypto's
/// `CCCryptor`, which buffers partial blocks across chunks and strips PKCS7
/// padding on `finalize()`. On non-Apple platforms (CI / fuzzing only —
/// AutoFill is Apple-only) the CBC path buffers and decrypts one-shot at
/// finalize: correct, just not memory-optimised where it doesn't matter.
final class DecryptingStreamReader: StreamingByteConsumer {
    private enum Backend {
        case chacha20(ChaCha20)
        case aesCBC(StreamingAESCBCDecryptor)
    }

    private var backend: Backend
    private let downstream: any StreamingByteConsumer

    init(header: Header, mainKey: SecureBytes, downstream: any StreamingByteConsumer) throws {
        self.downstream = downstream
        switch header.encryptionAlgorithm {
        case .AES256CBC:
            let keyData = mainKey.withUnsafeBytes { Data($0.bindMemory(to: UInt8.self)) }
            backend = .aesCBC(try StreamingAESCBCDecryptor(key: keyData, iv: header.encryptionNonce))
        case .ChaCha20:
            let cipher = try mainKey.withUnsafeBytes { keyPtr -> ChaCha20 in
                try ChaCha20(key: Data(keyPtr.bindMemory(to: UInt8.self)), iv: header.encryptionNonce)
            }
            backend = .chacha20(cipher)
        }
    }

    func consume(_ chunk: Data) throws {
        guard !chunk.isEmpty else { return }
        switch backend {
        case let .chacha20(cipher):
            let out = Data(cipher.decrypt(Array(chunk)))
            if !out.isEmpty { try downstream.consume(out) }
        case let .aesCBC(dec):
            let out = try dec.update(chunk)
            if !out.isEmpty { try downstream.consume(out) }
        }
    }

    func finalize() throws {
        if case let .aesCBC(dec) = backend {
            let tail = try dec.finalize()
            if !tail.isEmpty { try downstream.consume(tail) }
        }
        try downstream.finalize()
    }
}

#if canImport(CommonCrypto)
/// PKCS7 streaming AES-256-CBC decryptor over CommonCrypto. `CCCryptorUpdate`
/// buffers partial blocks across chunk boundaries and holds back the final
/// block; `CCCryptorFinal` strips the PKCS7 padding. Mirror of the
/// write-side `StreamingAESCBCEncryptor`.
final class StreamingAESCBCDecryptor {
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
                    CCOperation(kCCDecrypt),
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

    private func run(
        input: Data,
        outCapacity: Int,
        _ op: (_ inPtr: UnsafeRawPointer?, _ outPtr: UnsafeMutableRawPointer, _ moved: inout Int) -> CCCryptorStatus
    ) throws -> Data {
        guard outCapacity > 0 else {
            // Still drive the operation (it may consume buffered input).
            var moved = 0
            var dummy: UInt8 = 0
            let status = withUnsafeMutablePointer(to: &dummy) { outPtr -> CCCryptorStatus in
                input.withUnsafeBytes { inBuf in
                    op(inBuf.baseAddress, outPtr, &moved)
                }
            }
            guard status == CCCryptorStatus(kCCSuccess) else {
                throw Error.cryptoFailure("CCCryptor op failed with status \(status)")
            }
            return Data()
        }
        var output = Data(count: outCapacity)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBuf -> CCCryptorStatus in
            input.withUnsafeBytes { inBuf in
                op(inBuf.baseAddress, outBuf.baseAddress!, &moved)
            }
        }
        guard status == CCCryptorStatus(kCCSuccess) else {
            throw Error.cryptoFailure("CCCryptor op failed with status \(status)")
        }
        output.removeSubrange(moved..<output.count)
        return output
    }
}
#else
/// Non-Apple fallback: buffer the whole ciphertext and one-shot decrypt at
/// finalize. Correct but not streaming — only reached on Linux (CI /
/// fuzzing), where the AutoFill memory budget is irrelevant.
final class StreamingAESCBCDecryptor {
    private let key: Data
    private let iv: Data
    private var buffer = Data()

    init(key: Data, iv: Data) throws {
        self.key = key
        self.iv = iv
    }

    func update(_ chunk: Data) throws -> Data {
        buffer.append(chunk)
        return Data()
    }

    func finalize() throws -> Data {
        try AES256CBC.decrypt(iv: iv, cipherText: buffer, key)
    }
}
#endif
