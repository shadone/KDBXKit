//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension UUID {
    /// Returns true if the UUID is invalid, all components of the UUID value are zeroes.
    var isZero: Bool {
        uuid.0 == 0 && uuid.1 == 0 && uuid.2 == 0 && uuid.3 == 0 &&
            uuid.4 == 0 && uuid.5 == 0 && uuid.6 == 0 && uuid.7 == 0 &&
            uuid.8 == 0 && uuid.9 == 0 && uuid.10 == 0 && uuid.11 == 0 &&
            uuid.12 == 0 && uuid.13 == 0 && uuid.14 == 0 && uuid.15 == 0
    }
}
