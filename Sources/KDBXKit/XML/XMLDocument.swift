//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
#if canImport(FoundationXML)
// On swift-corelibs-foundation (Linux) XMLParser lives in FoundationXML.
import FoundationXML
#endif

/// `<?xml version="..." encoding="..." standalone="..."?>` prolog.
///
/// Modeled separately from the element tree because it's a one-shot
/// document-level thing, not a child node. The writer always emits one;
/// the parser does not preserve it on read (Foundation's `XMLParser`
/// doesn't surface the declaration through its delegate API, and the
/// reader doesn't consume it anyway).
struct XMLDeclaration: Sendable, Equatable {
    var version: String = "1.0"
    var encoding: String? = "UTF-8"
    var standalone: String? = nil
}

/// An XML document: an optional declaration plus a single root element.
///
/// On read the document tree is built by `Foundation.XMLParser` (the SAX
/// frontend in swift-corelibs-foundation, libxml2-backed on Darwin), so
/// the actual XML parsing inherits decades of hardening against
/// malformed and adversarial input.
///
/// On write we use our own deterministic serializer because we care
/// about byte-for-byte stability — two writes of the same content must
/// produce identical output for the salt-regeneration round-trip
/// guarantees in `KDBXWriter`.
final class Document {
    enum ParseError: Swift.Error {
        /// `line` and `column` are 1-based, as reported by Foundation's
        /// parser. They may be 0 if the failure happened outside parser
        /// callbacks (e.g. input wasn't valid UTF-8).
        case malformed(reason: String, line: Int, column: Int)
        /// Document nested deeper than `maxNestingDepth`. Defense against
        /// stack exhaustion from pathological input.
        case nestingTooDeep(line: Int, column: Int)
    }

    /// Hard cap on element nesting depth. 1024 is well past any realistic
    /// vault — KDBX nests Group→Group→Group plus the fixed envelope of
    /// `KeePassFile/Root/Group` etc. The reader's own
    /// `maxGroupNestingDepth` is 100 for the semantic-Group layer.
    static let maxNestingDepth = 1024

    var declaration: XMLDeclaration?
    var root: Node?

    init() { }

    init(string: String) throws(ParseError) {
        guard let data = string.data(using: .utf8) else {
            throw .malformed(reason: "Input is not valid UTF-8", line: 0, column: 0)
        }
        try parse(data: data)
    }

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

    // MARK: - Foundation-backed parse

    private func parse(data: Data) throws(ParseError) {
        let delegate = XMLBuildDelegate()
        // Unqualified so the type resolves to FoundationXML.XMLParser on
        // Linux (where Foundation.XMLParser is a deprecated stub).
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        // Explicitly defensive: never resolve external entities (XXE), never
        // process namespaces (KDBX doesn't use them and we'd rather see
        // `xmlns:` as a plain attribute if it ever appears).
        parser.shouldProcessNamespaces = false
        parser.shouldReportNamespacePrefixes = false
        parser.shouldResolveExternalEntities = false

        let ok = parser.parse()

        if let captured = delegate.capturedError {
            throw captured
        }
        if !ok {
            let line = parser.lineNumber
            let column = parser.columnNumber
            let reason = parser.parserError?.localizedDescription
                ?? "Unknown XML parse failure"
            throw .malformed(reason: reason, line: line, column: column)
        }

        // swift-corelibs-foundation's XMLParser can report success on an
        // input that produced no root element (e.g. "" or "not xml at all"
        // depending on libxml2's tolerance). Treat a missing root as a
        // parse error so callers see the same typed failure across
        // platforms.
        guard let parsedRoot = delegate.root else {
            throw .malformed(
                reason: "XML input produced no root element",
                line: parser.lineNumber,
                column: parser.columnNumber
            )
        }
        root = parsedRoot
        // Declaration is not surfaced by Foundation's parser; leave nil.
        // The writer always sets a fresh declaration before serializing.
    }
}

/// Builds a `Document` tree from `Foundation.XMLParser`'s SAX events.
///
/// State machine:
/// - `stack` is the chain of open elements from root down to the current
///   open element. Push on `didStartElement`, pop on `didEndElement`.
/// - `textBuffer` accumulates characters/CDATA between events; flushed
///   on element start/end so adjacent text and CDATA blocks merge into a
///   single text node (matches `Node.addText` semantics).
/// - On `didEndElement`, pure-whitespace text children are stripped if
///   the element also has element children. This is the standard
///   "ignorable whitespace" treatment: KDBX never uses mixed content, so
///   the indentation between `<X>` and `<Y>` siblings is noise.
/// - `capturedError` short-circuits the parse if anything fails: either
///   a depth cap violation we raised ourselves, or a parser-reported
///   syntax error. Once set, subsequent delegate callbacks ignore.
private final class XMLBuildDelegate: NSObject, XMLParserDelegate {
    var root: Node?
    var capturedError: Document.ParseError?

    private var stack: [Node] = []
    private var textBuffer: String = ""

    private func flushText() {
        guard !textBuffer.isEmpty else { return }
        if let top = stack.last {
            top.addText(textBuffer)
        }
        textBuffer = ""
    }

    func parser(
        _ parser: XMLParser,
        didStartElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?,
        attributes attributeDict: [String: String]
    ) {
        if capturedError != nil { return }

        if stack.count >= Document.maxNestingDepth {
            capturedError = .nestingTooDeep(
                line: parser.lineNumber,
                column: parser.columnNumber
            )
            parser.abortParsing()
            return
        }

        flushText()

        let element = Node.element(name: elementName)
        // Foundation gives attributes as a Dictionary, so the source-order
        // is lost. Sort by name to keep our output deterministic — two
        // parses of the same input yield byte-identical re-serialized
        // output, which `regenerateSalts: false` relies on transitively.
        element.attributes = attributeDict
            .sorted { $0.key < $1.key }
            .map { (name: $0.key, value: $0.value) }

        if let parent = stack.last {
            element.parent = parent
            parent.children.append(element)
        } else {
            root = element
        }
        stack.append(element)
    }

    func parser(
        _ parser: XMLParser,
        didEndElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?
    ) {
        if capturedError != nil { return }
        flushText()

        guard let closing = stack.popLast() else { return }

        let hasElementChild = closing.children.contains { $0.kind == .element }
        if hasElementChild {
            closing.children.removeAll { child in
                child.kind == .text
                    && child.value.unicodeScalars.allSatisfy(Node.isXMLWhitespace)
            }
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if capturedError != nil { return }
        textBuffer.append(string)
    }

    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        if capturedError != nil { return }
        if let s = String(data: CDATABlock, encoding: .utf8) {
            textBuffer.append(s)
        }
    }

    func parser(_ parser: XMLParser, parseErrorOccurred parseError: any Error) {
        if capturedError == nil {
            capturedError = .malformed(
                reason: parseError.localizedDescription,
                line: parser.lineNumber,
                column: parser.columnNumber
            )
        }
    }
}
