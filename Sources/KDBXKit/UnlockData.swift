//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

public struct UnlockData {
    let masterPassword: String?
    let keyFile: Data?

    public init(masterPassword: String, keyFile: Data? = nil) {
        self.masterPassword = masterPassword
        self.keyFile = keyFile
    }

    public init(keyFile: Data) {
        masterPassword = nil
        self.keyFile = keyFile
    }
}
