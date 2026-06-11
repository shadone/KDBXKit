//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Renders a `Document` back to XML text.
///
/// Formatting matches what KDBX writers conventionally emit:
/// - One element per line, with the configured `indentation` per depth
/// - Text-only elements collapse to `<X>value</X>` on a single line
/// - Empty elements emit as `<X/>`
/// - The declaration goes on its own first line, no trailing blank line
///
/// The output is deterministic: same input tree → byte-identical
/// output. KDBXWriter's `regenerateSalts: false` round-trip test
/// relies on that.
struct XMLSerializer {
    let indentation: String

    init(indentation: String) {
        self.indentation = indentation
    }

    func serialize(_ document: Document) -> String {
        var out = ""
        if let declaration = document.declaration {
            write(declaration, into: &out)
            out.append("\n")
        }
        if let root = document.root {
            write(root, depth: 0, into: &out)
            out.append("\n")
        }
        return out
    }

    private func write(_ declaration: XMLDeclaration, into out: inout String) {
        out.append("<?xml version=\"")
        out.append(escapeAttribute(declaration.version))
        out.append("\"")
        if let encoding = declaration.encoding {
            out.append(" encoding=\"")
            out.append(escapeAttribute(encoding))
            out.append("\"")
        }
        if let standalone = declaration.standalone {
            out.append(" standalone=\"")
            out.append(escapeAttribute(standalone))
            out.append("\"")
        }
        out.append("?>")
    }

    private func write(_ node: Node, depth: Int, into out: inout String) {
        switch node.kind {
        case .text:
            out.append(escapeText(node.value))
        case .element:
            writeElement(node, depth: depth, into: &out)
        }
    }

    private func writeElement(_ element: Node, depth: Int, into out: inout String) {
        let indent = String(repeating: indentation, count: depth)
        out.append(indent)
        out.append("<")
        out.append(element.name)
        for attr in element.attributes {
            out.append(" ")
            out.append(attr.name)
            out.append("=\"")
            out.append(escapeAttribute(attr.value))
            out.append("\"")
        }

        if element.children.isEmpty {
            out.append("/>")
            return
        }

        // If every child is text, collapse onto one line.
        let allText = element.children.allSatisfy { $0.kind == .text }
        if allText {
            out.append(">")
            for child in element.children {
                out.append(escapeText(child.value))
            }
            out.append("</")
            out.append(element.name)
            out.append(">")
            return
        }

        // Mixed or element-only content: child elements each on their own line.
        out.append(">")
        for child in element.children {
            // Skip stray empty text nodes between elements (parser
            // doesn't generate them, but be defensive).
            if child.kind == .text {
                if child.value.unicodeScalars.allSatisfy(Node.isXMLWhitespace) {
                    continue
                }
                out.append("\n")
                out.append(String(repeating: indentation, count: depth + 1))
                out.append(escapeText(child.value))
                continue
            }
            out.append("\n")
            writeElement(child, depth: depth + 1, into: &out)
        }
        out.append("\n")
        out.append(indent)
        out.append("</")
        out.append(element.name)
        out.append(">")
    }

    /// Escape characters that XML 1.0 §2.4 says aren't allowed raw in text.
    /// We escape `&`, `<`, `>`. `>` isn't strictly required raw except inside
    /// `]]>`, but escaping it everywhere matches what most XML emitters do
    /// and keeps the output safe under any parser.
    ///
    /// `\r` is escaped as `&#13;` because XML 1.0 §2.11 line-end
    /// normalization would otherwise rewrite a raw CR to LF on parse,
    /// silently corrupting any KDBX field that legitimately contains a
    /// carriage return.
    ///
    /// Scalars outside the XML 1.0 §2.2 `Char` production (e.g. `0x01`,
    /// `0x0B`) are replaced with U+FFFD — they're illegal in a document
    /// even as character references, so emitting them raw would produce
    /// a vault no client (including this library) can reopen. KeePass
    /// sanitizes on write for the same reason (`StrUtil.SafeXmlString`).
    private func escapeText(_ s: String) -> String {
        var result = ""
        result.reserveCapacity(s.utf8.count)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "&": result.append("&amp;")
            case "<": result.append("&lt;")
            case ">": result.append("&gt;")
            case "\r": result.append("&#13;")
            default:
                result.unicodeScalars.append(Self.isXMLChar(scalar) ? scalar : "\u{FFFD}")
            }
        }
        return result
    }

    private func escapeAttribute(_ s: String) -> String {
        var result = ""
        result.reserveCapacity(s.utf8.count)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "&": result.append("&amp;")
            case "<": result.append("&lt;")
            case ">": result.append("&gt;")
            case "\"": result.append("&quot;")
            case "\n": result.append("&#10;")
            case "\r": result.append("&#13;")
            case "\t": result.append("&#9;")
            default:
                result.unicodeScalars.append(Self.isXMLChar(scalar) ? scalar : "\u{FFFD}")
            }
        }
        return result
    }

    /// XML 1.0 §2.2 `Char` production. Surrogates can't occur in a
    /// `Unicode.Scalar`, so the only reachable exclusions are the C0
    /// controls (minus tab/LF/CR) and U+FFFE/U+FFFF.
    private static func isXMLChar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x9, 0xA, 0xD, 0x20...0xD7FF, 0xE000...0xFFFD, 0x10000...0x10FFFF:
            return true
        default:
            return false
        }
    }
}
