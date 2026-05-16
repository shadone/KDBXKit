//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

extension Node {
    var fullyQualifiedName: String {
        guard let parentFQN = parent?.fullyQualifiedName else {
            return name
        }
        return parentFQN + "." + name
    }
}
