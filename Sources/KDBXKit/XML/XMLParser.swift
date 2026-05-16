//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Minimal XML 1.0 parser for KDBX documents.
///
/// Scope:
/// - Element start / end / self-close tags
/// - Attributes with `"` or `'` quotes
/// - Text content with `&amp; &lt; &gt; &quot; &apos;` and numeric (`&#N;`, `&#xN;`) entities
/// - CDATA sections (treated as text)
/// - Comments and processing instructions (skipped)
/// - XML declaration `<?xml ... ?>`
/// - UTF-8 BOM is stripped if present
///
/// Out of scope: DTDs, external entities, namespaces (we don't strip
/// `xmlns:` — they round-trip as plain attributes, which is what KDBX
/// does anyway).
struct XMLParser {
    private let scalars: [Unicode.Scalar]
    private var position: Int = 0

    struct ParsedDocument {
        var declaration: XMLDeclaration?
        var root: Node?
    }

    init(input: String) {
        var scalars = Array(input.unicodeScalars)
        // Strip UTF-8 BOM (U+FEFF) if present.
        if scalars.first == "\u{FEFF}" {
            scalars.removeFirst()
        }
        self.scalars = scalars
    }

    mutating func parse() throws(Document.ParseError) -> ParsedDocument {
        var doc = ParsedDocument()

        skipWhitespace()

        if peeks("<?xml") {
            doc.declaration = try parseXMLDeclaration()
            skipWhitespace()
        }

        // Skip any leading comments / PIs (e.g. `<?xml-stylesheet ... ?>`).
        while position < scalars.count {
            if peeks("<!--") {
                try skipComment()
                skipWhitespace()
            } else if peeks("<?") {
                try skipProcessingInstruction()
                skipWhitespace()
            } else if peeks("<!DOCTYPE") {
                try skipDoctype()
                skipWhitespace()
            } else {
                break
            }
        }

        guard position < scalars.count else {
            throw .malformed(reason: "Missing root element", position: position)
        }
        guard peek() == "<" else {
            throw .malformed(reason: "Expected root element start tag", position: position)
        }

        doc.root = try parseElement()

        // Trailing whitespace and comments are fine; anything else is malformed.
        skipWhitespace()
        while position < scalars.count {
            if peeks("<!--") {
                try skipComment()
            } else if peeks("<?") {
                try skipProcessingInstruction()
            } else {
                throw .malformed(reason: "Trailing content after root element", position: position)
            }
            skipWhitespace()
        }

        return doc
    }

    // MARK: - Element

    private mutating func parseElement() throws(Document.ParseError) -> Node {
        guard consume("<") else {
            throw .malformed(reason: "Expected '<'", position: position)
        }

        let name = try parseName()
        let attributes = try parseAttributes()

        skipWhitespace()

        if consume("/") {
            guard consume(">") else {
                throw .malformed(reason: "Expected '>' after '/' in self-closing tag", position: position)
            }
            let element = Node.element(name: name)
            element.attributes = attributes
            return element
        }

        guard consume(">") else {
            throw .malformed(reason: "Expected '>' in start tag for '\(name)'", position: position)
        }

        let element = Node.element(name: name)
        element.attributes = attributes
        try parseChildren(of: element)

        // End tag.
        guard consume("<") && consume("/") else {
            throw .malformed(reason: "Expected end tag for '\(name)'", position: position)
        }
        let endName = try parseName()
        guard endName == name else {
            throw .malformed(reason: "Mismatched end tag: expected '\(name)', got '\(endName)'", position: position)
        }
        skipWhitespace()
        guard consume(">") else {
            throw .malformed(reason: "Expected '>' in end tag for '\(name)'", position: position)
        }

        return element
    }

    private mutating func parseChildren(of element: Node) throws(Document.ParseError) {
        var textBuffer = ""

        func flushText() {
            if !textBuffer.isEmpty {
                element.addText(textBuffer)
                textBuffer = ""
            }
        }

        while position < scalars.count {
            if peek() == "<" {
                // Branch on what comes next.
                if peeks("<!--") {
                    flushText()
                    try skipComment()
                } else if peeks("<![CDATA[") {
                    textBuffer += try parseCDATA()
                } else if peeks("<?") {
                    flushText()
                    try skipProcessingInstruction()
                } else if peeks("</") {
                    flushText()
                    stripIgnorableWhitespace(of: element)
                    return
                } else {
                    flushText()
                    let child = try parseElement()
                    child.parent = element
                    element.children.append(child)
                }
            } else if peek() == "&" {
                textBuffer.unicodeScalars.append(try parseEntity())
            } else {
                textBuffer.unicodeScalars.append(scalars[position])
                position += 1
            }
        }

        // Reached EOF without seeing the closing tag.
        throw .malformed(reason: "Unexpected EOF inside element '\(element.name)'", position: position)
    }

    /// Drop pure-whitespace text children from an element that also has
    /// element children. This is the standard XML "ignorable whitespace"
    /// treatment — pugixml does it by default, and KDBX never uses mixed
    /// content, so the indentation between `<X>` and `<Y>` siblings is
    /// noise the reader shouldn't have to filter on every walk.
    private func stripIgnorableWhitespace(of element: Node) {
        let hasElementChild = element.children.contains { $0.kind == .element }
        guard hasElementChild else { return }
        element.children.removeAll { child in
            child.kind == .text
                && child.value.unicodeScalars.allSatisfy { isWhitespace($0) }
        }
    }

    private func isWhitespace(_ c: Unicode.Scalar) -> Bool {
        c == " " || c == "\t" || c == "\n" || c == "\r"
    }

    // MARK: - Attributes

    private mutating func parseAttributes() throws(Document.ParseError) -> [(name: String, value: String)] {
        var attrs: [(name: String, value: String)] = []
        while true {
            skipWhitespace()
            // End of start tag — either `>` or `/>`.
            if position >= scalars.count {
                throw .malformed(reason: "EOF inside start tag", position: position)
            }
            let c = scalars[position]
            if c == ">" || c == "/" { return attrs }

            let name = try parseName()
            skipWhitespace()
            guard consume("=") else {
                throw .malformed(reason: "Expected '=' after attribute name '\(name)'", position: position)
            }
            skipWhitespace()
            let value = try parseAttributeValue()
            attrs.append((name: name, value: value))
        }
    }

    private mutating func parseAttributeValue() throws(Document.ParseError) -> String {
        guard position < scalars.count else {
            throw .malformed(reason: "EOF in attribute value", position: position)
        }
        let quote = scalars[position]
        guard quote == "\"" || quote == "'" else {
            throw .malformed(reason: "Expected quoted attribute value", position: position)
        }
        position += 1

        var result = ""
        while position < scalars.count {
            let c = scalars[position]
            if c == quote {
                position += 1
                return result
            }
            if c == "&" {
                result.unicodeScalars.append(try parseEntity())
            } else if c == "<" {
                throw .malformed(reason: "'<' not allowed in attribute value", position: position)
            } else {
                result.unicodeScalars.append(c)
                position += 1
            }
        }
        throw .malformed(reason: "EOF in attribute value", position: position)
    }

    // MARK: - Names

    private mutating func parseName() throws(Document.ParseError) -> String {
        let start = position
        while position < scalars.count, isNameChar(scalars[position]) {
            position += 1
        }
        guard position > start else {
            throw .malformed(reason: "Expected name", position: position)
        }
        return String(String.UnicodeScalarView(scalars[start..<position]))
    }

    /// XML 1.0 §2.3 — NameStartChar / NameChar. We accept the practical
    /// subset (letters, digits, `_`, `-`, `:`, `.`, non-ASCII letters).
    /// KDBX never emits unusual names so this is enough.
    private func isNameChar(_ c: Unicode.Scalar) -> Bool {
        switch c {
        case "a"..."z", "A"..."Z", "0"..."9", "_", "-", ".", ":":
            return true
        default:
            return c.value >= 0x80
        }
    }

    // MARK: - Entities

    private mutating func parseEntity() throws(Document.ParseError) -> Unicode.Scalar {
        let start = position
        guard consume("&") else {
            throw .malformed(reason: "Expected '&'", position: position)
        }

        // Numeric: `&#N;` or `&#xN;`.
        if consume("#") {
            let isHex = consume("x") || consume("X")
            let numStart = position
            while position < scalars.count, scalars[position] != ";" {
                position += 1
            }
            let body = String(String.UnicodeScalarView(scalars[numStart..<position]))
            guard consume(";") else {
                throw .malformed(reason: "Unterminated numeric entity", position: position)
            }
            let codepoint: UInt32?
            if isHex {
                codepoint = UInt32(body, radix: 16)
            } else {
                codepoint = UInt32(body, radix: 10)
            }
            guard let cp = codepoint, let scalar = Unicode.Scalar(cp) else {
                throw .malformed(reason: "Invalid numeric entity '\(body)'", position: start)
            }
            return scalar
        }

        let nameStart = position
        while position < scalars.count, scalars[position] != ";" {
            position += 1
        }
        let name = String(String.UnicodeScalarView(scalars[nameStart..<position]))
        guard consume(";") else {
            throw .malformed(reason: "Unterminated entity '\(name)'", position: position)
        }
        switch name {
        case "amp": return "&"
        case "lt": return "<"
        case "gt": return ">"
        case "quot": return "\""
        case "apos": return "'"
        default:
            throw .malformed(reason: "Unknown entity '&\(name);'", position: start)
        }
    }

    // MARK: - CDATA / Comments / PI / DOCTYPE / Declaration

    private mutating func parseCDATA() throws(Document.ParseError) -> String {
        guard consume("<![CDATA[") else {
            throw .malformed(reason: "Expected '<![CDATA['", position: position)
        }
        let start = position
        while position < scalars.count {
            if scalars[position] == "]",
               position + 2 < scalars.count,
               scalars[position + 1] == "]",
               scalars[position + 2] == ">"
            {
                let text = String(String.UnicodeScalarView(scalars[start..<position]))
                position += 3
                return text
            }
            position += 1
        }
        throw .malformed(reason: "Unterminated CDATA", position: position)
    }

    private mutating func skipComment() throws(Document.ParseError) {
        guard consume("<!--") else {
            throw .malformed(reason: "Expected '<!--'", position: position)
        }
        while position < scalars.count {
            if scalars[position] == "-",
               position + 2 < scalars.count,
               scalars[position + 1] == "-",
               scalars[position + 2] == ">"
            {
                position += 3
                return
            }
            position += 1
        }
        throw .malformed(reason: "Unterminated comment", position: position)
    }

    private mutating func skipProcessingInstruction() throws(Document.ParseError) {
        guard consume("<?") else {
            throw .malformed(reason: "Expected '<?'", position: position)
        }
        while position < scalars.count {
            if scalars[position] == "?",
               position + 1 < scalars.count,
               scalars[position + 1] == ">"
            {
                position += 2
                return
            }
            position += 1
        }
        throw .malformed(reason: "Unterminated processing instruction", position: position)
    }

    private mutating func skipDoctype() throws(Document.ParseError) {
        // `<!DOCTYPE` ... `>` — we don't care about anything inside.
        // KDBX never emits a DOCTYPE; we tolerate it for robustness.
        guard consume("<!DOCTYPE") else {
            throw .malformed(reason: "Expected '<!DOCTYPE'", position: position)
        }
        var depth = 1
        while position < scalars.count, depth > 0 {
            let c = scalars[position]
            if c == "<" { depth += 1 }
            if c == ">" { depth -= 1 }
            position += 1
            if depth == 0 { return }
        }
        throw .malformed(reason: "Unterminated DOCTYPE", position: position)
    }

    private mutating func parseXMLDeclaration() throws(Document.ParseError) -> XMLDeclaration {
        guard consume("<?xml") else {
            throw .malformed(reason: "Expected '<?xml'", position: position)
        }
        // Parse attribute-like pairs until `?>`.
        var attrs: [(name: String, value: String)] = []
        while true {
            skipWhitespace()
            if peeks("?>") {
                position += 2
                break
            }
            if position >= scalars.count {
                throw .malformed(reason: "Unterminated XML declaration", position: position)
            }
            let name = try parseName()
            skipWhitespace()
            guard consume("=") else {
                throw .malformed(reason: "Expected '=' in XML declaration", position: position)
            }
            skipWhitespace()
            let value = try parseAttributeValue()
            attrs.append((name: name, value: value))
        }

        var declaration = XMLDeclaration(version: "1.0", encoding: nil, standalone: nil)
        for (name, value) in attrs {
            switch name {
            case "version": declaration.version = value
            case "encoding": declaration.encoding = value
            case "standalone": declaration.standalone = value
            default: break
            }
        }
        return declaration
    }

    // MARK: - Cursor helpers

    private func peek() -> Unicode.Scalar? {
        position < scalars.count ? scalars[position] : nil
    }

    private func peeks(_ s: String) -> Bool {
        let target = Array(s.unicodeScalars)
        guard position + target.count <= scalars.count else { return false }
        for i in 0..<target.count where scalars[position + i] != target[i] {
            return false
        }
        return true
    }

    private mutating func consume(_ s: String) -> Bool {
        if peeks(s) {
            position += s.unicodeScalars.count
            return true
        }
        return false
    }

    private mutating func consume(_ c: Unicode.Scalar) -> Bool {
        if position < scalars.count, scalars[position] == c {
            position += 1
            return true
        }
        return false
    }

    private mutating func skipWhitespace() {
        while position < scalars.count {
            switch scalars[position] {
            case " ", "\t", "\n", "\r":
                position += 1
            default:
                return
            }
        }
    }
}

