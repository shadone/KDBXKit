//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import CryptoSwift
import Foundation

/// Streaming encryptor for the KDBX main payload. AES-256-CBC uses
/// CryptoSwift's `BlockEncryptor` (PKCS7-padded; buffers
/// non-block-aligned input across calls; emits final padded block on
/// `isLast: true`). ChaCha20 uses KDBXKit's stateful `ChaCha20`
/// stream cipher (no padding, every byte in produces one byte out
/// immediately).
internal final class EncryptingStreamWriter: StreamingByteConsumer {
    private enum Backend {
        case aesCBC(any Cryptor & Updatable)
        case chacha20(ChaCha20)
    }
    private var backend: Backend
    private let downstream: any StreamingByteConsumer

    init(header: Header, mainKey: SecureBytes, downstream: any StreamingByteConsumer) throws {
        self.downstream = downstream
        switch header.encryptionAlgorithm {
        case .AES256CBC:
            let encryptor = try mainKey.withUnsafeBytes { keyPtr -> any Cryptor & Updatable in
                try CryptoSwift.AES(
                    key: Array(keyPtr.bindMemory(to: UInt8.self)),
                    blockMode: CBC(iv: Array(header.encryptionNonce)),
                    padding: .pkcs7
                ).makeEncryptor()
            }
            self.backend = .aesCBC(encryptor)
        case .ChaCha20:
            let cipher = try mainKey.withUnsafeBytes { keyPtr -> ChaCha20 in
                try ChaCha20(
                    key: Data(keyPtr.bindMemory(to: UInt8.self)),
                    iv: header.encryptionNonce
                )
            }
            self.backend = .chacha20(cipher)
        }
    }

    func consume(_ chunk: Data) throws {
        try drive(chunk: Array(chunk), isLast: false)
    }

    func finalize() throws {
        try drive(chunk: [], isLast: true)
        try downstream.finalize()
    }

    private func drive(chunk: [UInt8], isLast: Bool) throws {
        switch backend {
        case .aesCBC(var enc):
            let inputSlice: ArraySlice<UInt8> = ArraySlice(chunk)
            let encrypted: [UInt8] = try enc.update(withBytes: inputSlice, isLast: isLast)
            backend = .aesCBC(enc)
            if !encrypted.isEmpty {
                try downstream.consume(Data(encrypted))
            }
        case .chacha20(let cipher):
            if !chunk.isEmpty {
                let out = cipher.encrypt(chunk)
                let outData = Data(out)
                if !outData.isEmpty {
                    try downstream.consume(outData)
                }
            }
        }
    }
}
