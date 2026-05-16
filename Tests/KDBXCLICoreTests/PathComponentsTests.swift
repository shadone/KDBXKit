//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXCLICore

@Suite("PathComponents")
struct PathComponentsTests {
    @Test("plain segments split on /")
    func plain() {
        let p = PathComponents(raw: "Banking/Chase")
        #expect(p.segments == ["Banking", "Chase"])
        #expect(!p.isRoot)
    }

    @Test("leading slash is dropped")
    func leadingSlash() {
        let p = PathComponents(raw: "/Banking/Chase")
        #expect(p.segments == ["Banking", "Chase"])
    }

    @Test("trailing slash is dropped")
    func trailingSlash() {
        let p = PathComponents(raw: "Banking/Chase/")
        #expect(p.segments == ["Banking", "Chase"])
    }

    @Test("collapsed slashes produce no empty segments")
    func collapsedSlashes() {
        let p = PathComponents(raw: "//Banking///Chase//")
        #expect(p.segments == ["Banking", "Chase"])
    }

    @Test("/ alone is root")
    func rootOnly() {
        let p = PathComponents(raw: "/")
        #expect(p.segments.isEmpty)
        #expect(p.isRoot)
    }

    @Test("empty string is root")
    func emptyIsRoot() {
        let p = PathComponents(raw: "")
        #expect(p.isRoot)
    }
}
