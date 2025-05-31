//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

protocol Decryptable {
    func decrypt(_ input: any DataProtocol) -> any DataProtocol
}
