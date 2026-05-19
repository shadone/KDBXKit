//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Property-based and fuzz tests for the XML reader/writer pair.
///
/// The KDBX read/write path round-trips data through `Document` ↔ XML
/// bytes on every save. Bugs in either direction silently corrupt
/// vaults, so we want broader coverage than a hand-written fixture
/// suite can offer.
///
/// The tests use a small deterministic PRNG (`SeededRandom`) so a
/// failure can be reproduced from its seed. The tree generator is
/// biased to the shape KDBX actually uses: never mixed content (an
/// element has either text children or element children, never both),
/// no empty text nodes, no pure-whitespace text content. That bias is
/// deliberate — XML's mixed-content and whitespace-normalization rules
/// are intricate and we only need to be right on the shapes KDBX
/// emits.
@Suite("XML property-based round-trip + fuzz")
struct XMLPropertyTests {
    // MARK: - Round-trip

    @Test("Random KDBX-shaped trees survive serialize → parse")
    func roundTripPreservesTree() throws {
        var rng = SeededRandom(seed: 0xA11CE5EED)
        for iteration in 0..<200 {
            let original = generateTree(rng: &rng, maxDepth: 4, maxBreadth: 4)
            let doc = Document()
            doc.declaration = XMLDeclaration()
            doc.root = original

            let bytes = doc.xmlData(indentation: "\t")
            let serialized = String(data: bytes, encoding: .utf8) ?? ""

            let reparsed = try Document(string: serialized)
            guard let parsedRoot = reparsed.root else {
                Issue.record("iteration \(iteration): re-parse produced no root")
                continue
            }
            #expect(
                treesEqual(original, parsedRoot),
                "iteration \(iteration) — serialized form:\n\(serialized)"
            )
        }
    }

    @Test("Serialize → parse → serialize is byte-stable")
    func serializerIsIdempotent() throws {
        var rng = SeededRandom(seed: 0xDEADBEEF)
        for iteration in 0..<200 {
            let tree = generateTree(rng: &rng, maxDepth: 4, maxBreadth: 4)
            let doc1 = Document()
            doc1.declaration = XMLDeclaration()
            doc1.root = tree
            let bytes1 = doc1.xmlData(indentation: "\t")

            let reparsed = try Document(string: String(data: bytes1, encoding: .utf8) ?? "")
            // Foundation's parser doesn't surface the XML declaration
            // through its delegate API, so a re-parsed Document has
            // declaration == nil and would serialize without a prolog.
            // Re-set it to match the original — KDBXWriter does the same
            // unconditionally before every write.
            reparsed.declaration = XMLDeclaration()
            let bytes2 = reparsed.xmlData(indentation: "\t")

            #expect(bytes1 == bytes2, "iteration \(iteration): second serialization diverged")
        }
    }

    // MARK: - Fuzz

    @Test("Random byte input never crashes the parser")
    func parserSurvivesRandomBytes() {
        var rng = SeededRandom(seed: 0xF022F022)
        for _ in 0..<2000 {
            let len = Int.random(in: 0...400, using: &rng)
            let bytes = Data((0..<len).map { _ in UInt8.random(in: 0...255, using: &rng) })
            let string = String(data: bytes, encoding: .utf8) ?? ""
            // The parser must either succeed or throw; never crash, never hang.
            _ = try? Document(string: string)
        }
    }

    @Test("Bit-flips of a valid document never crash the parser")
    func parserSurvivesMutationFuzz() {
        // Build a moderately-complex valid document once, then bit-flip
        // single bytes at random positions and feed each mutated copy
        // to the parser.
        var rng = SeededRandom(seed: 0xBEEFF1A9)
        let tree = generateTree(rng: &rng, maxDepth: 4, maxBreadth: 4)
        let doc = Document()
        doc.declaration = XMLDeclaration()
        doc.root = tree
        let baseline = doc.xmlData(indentation: "\t")
        var bytes = Array(baseline)

        for _ in 0..<2000 {
            guard !bytes.isEmpty else { break }
            let index = Int.random(in: 0..<bytes.count, using: &rng)
            let saved = bytes[index]
            bytes[index] ^= UInt8.random(in: 1...255, using: &rng)
            let string = String(data: Data(bytes), encoding: .utf8) ?? ""
            _ = try? Document(string: string)
            bytes[index] = saved
        }
    }

    @Test("Recursion cap rejects pathologically-nested input")
    func depthCapRejectsDeepNesting() throws {
        // Build an XML string with more open tags than the depth cap.
        let depth = Document.maxNestingDepth + 50
        var xml = "<?xml version=\"1.0\"?>"
        for _ in 0..<depth {
            xml += "<a>"
        }
        for _ in 0..<depth {
            xml += "</a>"
        }

        do {
            _ = try Document(string: xml)
            Issue.record("parser accepted document nested past the cap")
        } catch {
            // Either nestingTooDeep (we hit the cap first) or malformed
            // (Foundation tripped on something else) is acceptable —
            // the contract is "doesn't crash, throws cleanly".
        }
    }

    // MARK: - Generator

    /// Build a KDBX-shaped XML tree:
    /// - Every element is either empty, has exactly one text child, or has
    ///   one-or-more element children. Never mixed.
    /// - Attribute names are unique within an element.
    /// - Text content avoids the corner cases that XML's whitespace and
    ///   attribute normalization treats ambiguously (leading/trailing
    ///   whitespace, pure whitespace, CR characters).
    private func generateTree(
        rng: inout SeededRandom,
        maxDepth: Int,
        maxBreadth: Int,
        depth: Int = 0
    ) -> Node {
        let names = ["a", "Ab", "X1", "_y", "Elem", "Item", "Long_Name_2"]
        // Pick texts that exercise escaping (& < > " '), unicode, and
        // special-but-bounded content. No pure whitespace, no empty,
        // no leading/trailing whitespace.
        let texts = [
            "plain",
            "with & ampersand",
            "less<than and greater>than",
            "\"double\" and 'single' quotes",
            "unicode ñ æ 中 🎉",
            "embedded\ttab",
            "embedded\nnewline",
            // CR exercises XML 1.0 §2.11 line-end normalization: a raw
            // 0x0D would be silently rewritten to 0x0A on parse unless
            // the serializer escapes it as `&#13;`.
            "embedded\rcarriage",
            "windows\r\nline-ending",
        ]

        let name = names.randomElement(using: &rng)!
        let node = Node.element(name: name)

        // 0 to 3 attributes with unique names.
        let attrCount = Int.random(in: 0...3, using: &rng)
        for i in 0..<attrCount {
            node.attributes.append((
                name: "a\(i)",
                value: texts.randomElement(using: &rng)!,
            ))
        }
        // Pre-sort to match the parser's deterministic output.
        node.attributes.sort { $0.name < $1.name }

        // Pick one of three child modes — never mix.
        if depth >= maxDepth {
            // Leaf: empty or single text child.
            if Bool.random(using: &rng) {
                node.addText(texts.randomElement(using: &rng)!)
            }
            return node
        }
        switch Int.random(in: 0..<3, using: &rng) {
        case 0:
            break // empty
        case 1:
            node.addText(texts.randomElement(using: &rng)!)
        default:
            let breadth = Int.random(in: 1...maxBreadth, using: &rng)
            for _ in 0..<breadth {
                let kid = generateTree(
                    rng: &rng,
                    maxDepth: maxDepth,
                    maxBreadth: maxBreadth,
                    depth: depth + 1
                )
                kid.parent = node
                node.children.append(kid)
            }
        }
        return node
    }

    /// Structural equality. Attribute order is sorted on both sides so a
    /// parsed tree (where Foundation gave attributes as a `Dictionary`
    /// and we sorted by name) matches an original tree where we sorted
    /// explicitly.
    private func treesEqual(_ a: Node, _ b: Node) -> Bool {
        guard a.kind == b.kind else { return false }
        guard a.name == b.name else { return false }
        guard a.value == b.value else { return false }

        let aAttrs = a.attributes.sorted { $0.name < $1.name }
        let bAttrs = b.attributes.sorted { $0.name < $1.name }
        guard aAttrs.count == bAttrs.count else { return false }
        for (la, lb) in zip(aAttrs, bAttrs) where la.name != lb.name || la.value != lb.value {
            return false
        }

        guard a.children.count == b.children.count else { return false }
        for (lc, rc) in zip(a.children, b.children) where !treesEqual(lc, rc) {
            return false
        }
        return true
    }
}

/// splitmix64-based deterministic PRNG. Used so a failing test prints
/// a seed the developer can re-run to reproduce.
struct SeededRandom: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}
