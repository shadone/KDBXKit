//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// What kind of XML node this is.
///
/// KDBX XML is narrow: only element and text nodes appear in the body.
/// Comments and processing instructions are ignored on parse and never
/// emitted by the writer; the XML declaration is modeled separately on
/// `Document`, not as a node.
enum NodeKind: Sendable {
    case element
    case text
}

/// A node in an XML tree.
///
/// Element nodes carry `name` and `attributes`; their `value` is empty.
/// Text nodes carry `value`; their `name` is empty and they have no
/// children or attributes. The two are kept as one type so the
/// reader/writer can walk `children` uniformly (matches the API the
/// previous pugixml-backed library exposed).
final class Node {
    let kind: NodeKind
    let name: String
    var value: String
    var attributes: [(name: String, value: String)] = []
    // Internal mutability so the parser can append already-constructed
    // child nodes. External callers should still go through `addElement`
    // / `addText` to keep parent pointers in sync.
    var children: [Node] = []

    // `parent` is unowned because every child is appended via `addElement`
    // / `addText` which keeps the parent alive through `children`. The
    // parent owns the child, the child borrows back upward.
    weak var parent: Node?

    private init(kind: NodeKind, name: String, value: String) {
        self.kind = kind
        self.name = name
        self.value = value
    }

    static func element(name: String) -> Node {
        Node(kind: .element, name: name, value: "")
    }

    static func text(_ value: String) -> Node {
        Node(kind: .text, name: "", value: value)
    }

    func children(ofKind kind: NodeKind) -> [Node] {
        children.filter { $0.kind == kind }
    }

    @discardableResult
    func addElement(_ name: String) -> Node {
        let child = Node.element(name: name)
        child.parent = self
        children.append(child)
        return child
    }

    func addText(_ text: String) {
        let child = Node.text(text)
        child.parent = self
        children.append(child)
    }

    /// XML's S production (§2.3): SPACE | TAB | CR | LF. Matches the
    /// "ignorable whitespace" the parser already strips between element
    /// siblings, and is what the serializer uses to decide whether a
    /// stray text node between elements is just indentation noise.
    static func isXMLWhitespace(_ c: Unicode.Scalar) -> Bool {
        c == " " || c == "\t" || c == "\n" || c == "\r"
    }
}
