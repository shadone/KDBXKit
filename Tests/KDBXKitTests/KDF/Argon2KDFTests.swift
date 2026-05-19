//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Test
func Argon2KDF_argon2id() async throws {
    let password = SecureBytes(utf8: "password")
    let salt = Data("some salt".utf8)
    let result = try Argon2KDF.argon2id(
        password: password,
        params: .init(version: .v1_3, salt: salt, iterations: 16, memory: 32768 * 1024, parallelism: 2)
    )
    #expect(result.toData().hexString == "157f21dd3fdf7bafb76d2923ccaffa0b7be7cbae394709474d2bc66ee7b09d3e")
}

@Test
func Argon2KDF_argon2d() async throws {
    let password = SecureBytes(utf8: "password")
    let salt = Data("some salt".utf8)
    let result = try Argon2KDF.argon2d(
        password: password,
        params: .init(version: .v1_3, salt: salt, iterations: 16, memory: 32768 * 1024, parallelism: 2)
    )
    #expect(result.toData().hexString == "1ed3694706b2a49b8031836fd501152c386495f9a669481b74ad30732f55423b")
}
