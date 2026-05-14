//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

@Test
func AESKDF_single() async throws {
    let password = SecureBytes(utf8: "passwordpasswordpasswordpassword")
    let salt = Data("abcdefghjiklmnopabcdefghjiklmnop".utf8)
    let result = AESKDF.derive(salt: salt, rounds: 1, password)
    #expect(result.toData().hexString == "d3784e35d961f804249296eef568672550caed47ffdcc5ea19ed862553a4f251")
}

@Test
func AESKDFTest() async throws {
    let password = SecureBytes(Data(hexString: "5a77d1e9612d350b3734f6282259b7ff0a3f87d62cfef5f35e91a5604c0490a3")!)
    let salt = Data(hexString: "bff164e9044a359f4b473f882d83fe1e85f4e88ac6caf2c28f0c75e24c8e7569")!
    let result = AESKDF.derive(salt: salt, rounds: 1000, password)
    #expect(result.toData().hexString == "68a581af1d3aacc7506eab9ddb32abb192d10214fb08499a6be29d58d0f5c83a")
}
