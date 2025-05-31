//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension DataProtocol {
    func slice(_ range: Range<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: range.lowerBound)
        let end = index(startIndex, offsetBy: range.upperBound)
        return self[start..<end]
    }

    subscript(position: Int) -> Element {
        self[index(startIndex, offsetBy: position)]
    }
}

extension MutableDataProtocol {
    mutating func replaceSubrange<C>(_ subrange: Range<Int>, with newElements: C) where C: Collection, Element == C.Element {
        let start = index(startIndex, offsetBy: subrange.lowerBound)
        let end = index(startIndex, offsetBy: subrange.upperBound)
        replaceSubrange(start..<end, with: newElements)
    }
}
