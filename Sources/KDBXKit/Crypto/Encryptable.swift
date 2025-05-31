//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

protocol Encryptable {
    func encrypt(_ input: any DataProtocol) -> any DataProtocol
}
