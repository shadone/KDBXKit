//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Security

enum SecureRandom {
    /// Returns `length` bytes from the system CSPRNG. Crashes if the system
    /// random source fails (effectively never on Apple platforms — it would
    /// indicate the kernel is unhappy at a level where retry is pointless).
    static func bytes(_ length: Int) -> Data {
        precondition(length >= 0, "Length must be non-negative")
        var bytes = [UInt8](repeating: 0, count: length)
        let status = bytes.withUnsafeMutableBufferPointer { buffer in
            SecRandomCopyBytes(kSecRandomDefault, length, buffer.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed with status \(status)")
        return Data(bytes)
    }
}
