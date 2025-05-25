//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Nodal

struct DatabaseReader {
    let document: Document

    init(xmlDocument: String) {
        self.document = try! Document(string: xmlDocument)
    }

    mutating func parse() {
        //document.documentElement?.children
    }
}
