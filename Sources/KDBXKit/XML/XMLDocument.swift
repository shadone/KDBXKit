//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// `<?xml version="..." encoding="..." standalone="..."?>` prolog.
///
/// Modeled separately from the element tree because it's a one-shot
/// document-level thing, not a child node. The writer always emits one;
/// the parser preserves whatever it sees (or leaves nil if absent).
struct XMLDeclaration: Sendable, Equatable {
    var version: String = "1.0"
    var encoding: String? = "UTF-8"
    var standalone: String? = nil
}

/// An XML document: a declaration plus a single root element.
///
/// KDBX XML is constrained — no DTDs, no namespaces in practice, no
/// comments emitted, no processing instructions other than the
/// declaration. This type is internal to KDBXKit and the API surface
/// is just what the reader and writer need.
final class Document {
    enum ParseError: Swift.Error {
        case malformed(reason: String, position: Int)
    }

    var declaration: XMLDeclaration?
    var root: Node?

    init() {}

    init(string: String) throws(ParseError) {
        var parser = XMLParser(input: string)
        let parsed = try parser.parse()
        declaration = parsed.declaration
        root = parsed.root
    }

    var documentElement: Node? { root }

    @discardableResult
    func makeDocumentElement(name: String) -> Node {
        let element = Node.element(name: name)
        root = element
        return element
    }

    func xmlData(indentation: String) -> Data {
        let serialized = XMLSerializer(indentation: indentation).serialize(self)
        return Data(serialized.utf8)
    }
}
