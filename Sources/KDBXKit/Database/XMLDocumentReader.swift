//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

/// Overview of a KDBX file:
///
/// ```
///                                      This class:
/// 1. Header.
/// 2. SHA-256 hash of the header.
/// 3. HMAC-SHA-256 hash of the header.
/// 4. In HMAC-protected block stream:
///    a. Encrypted:
///       i. Compressed (optional):
///          - Inner header.
///          - XML document.             <<- parses XML document
/// ```
/// Mutable counter the reader uses to track its position in the inner
/// cipher keystream during the XML walk. Class-backed so recursive
/// `parse*` helpers can advance it without each one having to be
/// `mutating`.
private final class KeystreamCursor {
    var position: Int = 0
    func advance(by count: Int) { position += count }
}

/// Mutable bag of parser diagnostics. Lives in a class so the recursive
/// (non-mutating) `parse*` helpers can append without each one becoming
/// `mutating`. Surfaced via `XMLDocumentReader.collectedWarnings` and then
/// threaded into `KDBXContent.parserWarnings` so callers can see what was
/// dropped during a read — useful for catching unknown elements emitted
/// by other KDBX-aware tools that we don't yet model.
private final class ParserWarnings {
    var messages: [String] = []
    func add(_ message: String) { messages.append(message) }
}

/// Mutable collector for the `<Meta><Binaries>` pool harvested during a
/// KDBX 3.x parse. Class-backed for the same reason as ``ParserWarnings``:
/// recursive non-mutating `parse*` helpers need to append.
private final class InlineBinaryPoolCollector {
    var entries: [(id: UInt32, content: InnerHeader.BinaryContent)] = []
    func append(id: UInt32, content: InnerHeader.BinaryContent) {
        entries.append((id: id, content: content))
    }
}

struct XMLDocumentReader {
    enum Error: Swift.Error {
        case corrupted(reason: String)
    }

    /// XML serialization dialect for `<Times>` / `<Meta>` date fields.
    ///
    /// KDBX 4 packs dates as base64-encoded little-endian Int64 seconds
    /// since the .NET epoch (`0001-01-01T00:00:00Z`). KDBX 3.x writes
    /// ISO-8601 strings. Producers don't mix the two within one file, so
    /// the reader picks once at construction rather than format-sniffing
    /// per field.
    enum DateFormat: Sendable {
        /// Base64-encoded little-endian `Int64` seconds since 0001-01-01.
        /// KDBX 4 default.
        case dotNetTicksBase64
        /// ISO-8601 string (e.g. `"2020-01-15T10:00:00Z"`). KDBX 3.x.
        case iso8601
    }

    let document: Document

    var meta = KDBX.Meta()
    var root: KDBX.Root?

    /// Random-access keystream — the reader records each protected
    /// node's keystream offset instead of decrypting in line.
    let keystreamSource: KeystreamSource

    /// Date serialization dialect — set once at init based on the file's
    /// outer format version. See ``DateFormat``.
    private let dateFormat: DateFormat

    /// Binary pool harvested from `<Meta><Binaries>`. Empty for KDBX 4
    /// files (which store binaries in the inner header instead). The 3.x
    /// read pipeline migrates these into a synthesized
    /// ``InnerHeader.binaryContent`` so downstream code stays uniform.
    private let inlineBinaries = InlineBinaryPoolCollector()

    /// Binary pool extracted from the XML body. Ordered by the `ID`
    /// attribute on each `<Binary>` element so callers can rely on the
    /// index as the entry-side `<Value Ref="N"/>` target.
    var inlineBinaryPool: [InnerHeader.BinaryContent] {
        inlineBinaries.entries
            .sorted { $0.id < $1.id }
            .map(\.content)
    }

    /// Maps each on-disk pool `ID` to its index in ``inlineBinaryPool``.
    /// Entry `Ref` attributes carry the ID, which only equals the array
    /// index when IDs run contiguously from zero.
    private var inlineBinaryIDToIndex: [UInt32: Int] {
        var map: [UInt32: Int] = [:]
        for (index, entry) in inlineBinaries.entries.sorted(by: { $0.id < $1.id }).enumerated() {
            map[entry.id] = index
        }
        return map
    }

    /// Running offset into the inner-cipher keystream, boxed in a class
    /// so the recursive `parse*` walk can advance it without every
    /// function having to be `mutating`. Advances by `ciphertext.count`
    /// for each `Protected="True"` node encountered during the walk;
    /// emitted alongside the ciphertext into a
    /// `ProtectedString.Value.lazyInnerCipher` so each value can be
    /// decrypted independently on access.
    ///
    /// The writer consumes the keystream linearly in document order,
    /// so as long as the reader visits protected nodes in the same
    /// order (entries → strings → history → strings, recursively), the
    /// recorded offsets line up with what the writer produced.
    private let cursor = KeystreamCursor()

    private let warnings = ParserWarnings()

    /// Diagnostic messages collected during the parse: unknown elements,
    /// unknown attributes, malformed-but-tolerated values. Empty for files
    /// produced by `KDBXWriter` against the current model; non-empty
    /// indicates the source file contained something we silently dropped
    /// or repaired.
    var collectedWarnings: [String] { warnings.messages }

    init(
        xmlDocument: String,
        keystreamSource: KeystreamSource,
        dateFormat: DateFormat = .dotNetTicksBase64
    ) throws(Error) {
        do {
            document = try Document(string: xmlDocument)
        } catch let parseError {
            switch parseError {
            case let .malformed(reason, line, column):
                throw .corrupted(reason: "Malformed XML at line \(line), column \(column): \(reason)")
            case let .nestingTooDeep(line, column):
                throw .corrupted(reason: "XML nesting exceeds \(Document.maxNestingDepth) at line \(line), column \(column)")
            }
        }
        self.keystreamSource = keystreamSource
        self.dateFormat = dateFormat
    }

    /// Records a parser diagnostic. Both surfaces it via the os logger
    /// (debug-level, invisible by default) and accumulates it in
    /// `collectedWarnings` so tests / callers can see what got dropped.
    private func record(_ message: String) {
        let log = KDBXLog.parser
        log.debug("\(message)")
        warnings.add(message)
    }

    // MARK: Parse <datatype> helpers

    private func parseDate(_ string: String, node: Node) throws(Error) -> Date {
        switch dateFormat {
        case .dotNetTicksBase64:
            guard
                let secondsSinceDotnetEpoch = Data(base64Encoded: string)?.asInt64LE()
            else {
                throw .corrupted(reason: "Failed to parse date '\(string)' from \(node.fullyQualifiedName)")
            }
            return Date(secondsSinceDotNetEpoch: secondsSinceDotnetEpoch)

        case .iso8601:
            if let date = parseISO8601(string) {
                return date
            }
            throw .corrupted(reason: "Failed to parse ISO-8601 date '\(string)' from \(node.fullyQualifiedName)")
        }
    }

    /// Parse the ISO-8601 dialect KDBX 3.x writers use. KeePass / KeePassXC
    /// emit `YYYY-MM-DDThh:mm:ssZ`; we also accept fractional seconds and
    /// numeric offsets so a file produced by a less-canonical writer
    /// doesn't bomb the entire parse.
    private func parseISO8601(_ string: String) -> Date? {
        if let date = XMLDocumentReader.iso8601Plain.date(from: string) {
            return date
        }
        if let date = XMLDocumentReader.iso8601Fractional.date(from: string) {
            return date
        }
        return nil
    }

    /// `Z`-suffixed or `±HH:MM` ISO-8601 with second precision.
    // `ISO8601DateFormatter` is documented thread-safe by Apple (the
    // `DateFormatter` family explicitly says formatters are safe to share
    // across threads once configured), but Swift 6 strict concurrency
    // can't see the framework annotation. `nonisolated(unsafe)` asserts
    // the property we know to hold — cheaper than rebuilding a formatter
    // for every date in the file (a populated vault has thousands).
    private nonisolated(unsafe) static let iso8601Plain: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    /// Same as above but accepts fractional seconds.
    private nonisolated(unsafe) static let iso8601Fractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Parse a `<Meta><Binaries>` pool into ``collectedInlineBinaries``.
    ///
    /// Layout:
    /// ```xml
    /// <Binaries>
    ///   <Binary ID="0" Compressed="True">base64...</Binary>
    ///   <Binary ID="1" Protected="False">base64...</Binary>
    /// </Binaries>
    /// ```
    /// `Compressed="True"` means the decoded bytes are gzipped — we
    /// inflate so the in-memory pool always carries the raw payload, the
    /// same shape the 4.x inner-header pool uses. `Protected` follows the
    /// same convention as ``InnerHeader.BinaryContent.shouldBeProtected``.
    private func parseInlineBinariesPool(_ node: Node) throws(Error) {
        for child in node.children {
            guard child.name == "Binary" else {
                record("Unexpected element \(child.fullyQualifiedName)")
                continue
            }

            var id: UInt32?
            var compressed = false
            var protected = false

            for (name, value) in child.attributes {
                switch name {
                case "ID":
                    guard let parsed = UInt32(value) else {
                        throw .corrupted(reason: "Invalid Binary ID '\(value)' in \(child.fullyQualifiedName)")
                    }
                    id = parsed
                case "Compressed":
                    compressed = (value.lowercased() == "true")
                case "Protected":
                    protected = (value.lowercased() == "true")
                default:
                    record("Unexpected attribute '\(name)' in Binary in \(child.fullyQualifiedName)")
                }
            }

            guard let id else {
                throw .corrupted(reason: "Missing ID attribute on Binary in \(child.fullyQualifiedName)")
            }

            // The text content is base64. Empty payload is legal (an
            // intentionally empty attachment) and decodes to zero bytes.
            let base64 = text(in: child) ?? ""
            guard let decoded = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
                throw .corrupted(reason: "Invalid base64 in Binary ID=\(id) in \(child.fullyQualifiedName)")
            }

            // Protected pool binaries are XOR'd with the shared inner
            // keystream, consumed in document order — and since <Meta>
            // precedes <Root>, these bytes are taken before any entry
            // password. De-XOR first, then decompress (KeePass stores the
            // compressed bytes protected). Advancing the cursor keeps
            // every later protected value aligned.
            let stored: Data
            if protected {
                stored = keystreamSource.decrypt(ciphertext: decoded, at: cursor.position).toData()
                cursor.advance(by: decoded.count)
            } else {
                stored = decoded
            }

            let payload: Data
            if compressed, !stored.isEmpty {
                do {
                    payload = try LegacyBinaryDecompressor.gunzip(stored)
                } catch {
                    throw .corrupted(reason: "Failed to gunzip Binary ID=\(id): \(error)")
                }
            } else {
                payload = stored
            }

            if inlineBinaries.entries.contains(where: { $0.id == id }) {
                throw .corrupted(reason: "Duplicate Binary ID=\(id) in \(child.fullyQualifiedName)")
            }
            inlineBinaries.append(
                id: id,
                content: .init(shouldBeProtected: protected, data: payload)
            )
        }
    }

    private func parseNumber<T: FixedWidthInteger>(_ string: String, node: Node) throws(Error) -> T {
        guard let number = T(string) else {
            throw .corrupted(reason: "Failed to parse \(T.self) '\(string)' from \(node.fullyQualifiedName)")
        }
        return number
    }

    private func parseBool(_ string: String, node: Node) throws(Error) -> Bool {
        switch string {
        case "True":
            return true
        case "False":
            return false
        default:
            throw .corrupted(reason: "Failed to parse bool '\(string)' from \(node.fullyQualifiedName)")
        }
    }

    private func parseColor(_ string: String, node: Node) throws(Error) -> KDBX.Color {
        guard let color = KDBX.Color(stringValue: string) else {
            throw .corrupted(reason: "Failed to parse color '\(string)' from \(node.fullyQualifiedName)")
        }
        return color
    }

    private func parseValueOrNever<T: Sendable & FixedWidthInteger>(_ string: String, node: Node) throws(Error) -> KDBX.ValueOrNever<T> {
        // XSD specifies "-1" as the sentinel, but any negative is treated
        // as `.never` so a producer writing e.g. "-2" doesn't crash the reader.
        if let signed = Int64(string), signed < 0 {
            return .never
        }
        return try .value(parseNumber(string, node: node))
    }

    private func parseValueOrUnlimited<T: Sendable & FixedWidthInteger>(_ string: String, node: Node) throws(Error) -> KDBX.ValueOrUnlimited<T> {
        // XSD specifies "-1" as the sentinel, but any negative is treated
        // as `.unlimited` so a producer writing e.g. "-2" doesn't crash the reader.
        if let signed = Int64(string), signed < 0 {
            return .unlimited
        }
        return try .value(parseNumber(string, node: node))
    }

    /// Lenient counterpart to `parseNumber` for unsigned XSD fields that
    /// have no sentinel (`MaintenanceHistoryDays`, `UsageCount`). Returns
    /// nil instead of throwing on negative or otherwise-unparseable input,
    /// so a corrupt value drops the field rather than failing the whole load.
    private func parseLenientUnsigned<T: FixedWidthInteger & UnsignedInteger>(_ string: String, node: Node) -> T? {
        if let signed = Int64(string), signed < 0 {
            record("Negative value '\(string)' for unsigned field in \(node.fullyQualifiedName); dropping")
            return nil
        }
        guard let value = T(string) else {
            record("Failed to parse \(T.self) '\(string)' in \(node.fullyQualifiedName); dropping")
            return nil
        }
        return value
    }

    /// - parameter string: A 128-bit UUID encoded using Base64.
    private func parseUUID(_ string: String, node: Node) throws(Error) -> UUID {
        guard
            let uuidValue = Data(base64Encoded: string)?.asUUIDLE()
        else {
            throw .corrupted(reason: "Failed to parse UUID '\(string)' from \(node.fullyQualifiedName)")
        }
        return uuidValue
    }

    private func text(in node: Node) -> String? {
        let textNodes = node.children(ofKind: .text)

        var numberOfTextNodes = 0
        var result = ""
        for textNode in textNodes {
            result += textNode.value
            numberOfTextNodes += 1
        }

        return numberOfTextNodes == 0 ? nil : result
    }

    // MARK: Public API

    func parse() throws(Error) -> KDBX {
        guard let rootElement = document.root else {
            throw .corrupted(reason: "Missing root element")
        }

        guard rootElement.name == "KeePassFile" else {
            throw .corrupted(reason: "Invalid root element: \(rootElement.name)")
        }

        let (meta, root) = try parseKeepassFile(rootElement)
        var database = KDBX(meta: meta, root: root)

        // The <Meta><Binaries> pool is a KDBX 3.1 construct. A 4.x file
        // (dotNetTicksBase64 dates) storing binaries in the inner header
        // should never carry one — if it does, it's nonstandard: the 4.x
        // pipeline ignores the pool, so its attachments would be lost on
        // the next save and any entry Ref into it would dangle. Surface
        // that rather than silently remapping 4.x refs (which point at
        // the inner-header pool, not this one).
        if !inlineBinaries.entries.isEmpty {
            switch dateFormat {
            case .iso8601:
                // KDBX 3.1: entry Ref attributes carry the on-disk pool
                // ID, but the synthesized pool (``inlineBinaryPool``) is
                // positional — rewrite every Ref through the ID→index map
                // so downstream code (which treats refs as pool indices,
                // like 4.x) resolves the right attachment even when the
                // on-disk IDs have gaps.
                remapBinaryRefs(in: &database.root.group, using: inlineBinaryIDToIndex)
            case .dotNetTicksBase64:
                record("Ignoring nonstandard <Meta><Binaries> pool (\(inlineBinaries.entries.count) entries) in a KDBX 4 file")
            }
        }
        return database
    }

    private func remapBinaryRefs(in group: inout KDBX.Group, using map: [UInt32: Int]) {
        for i in group.entries.indices {
            remapBinaryRefs(in: &group.entries[i], using: map)
            for h in group.entries[i].history.indices {
                remapBinaryRefs(in: &group.entries[i].history[h], using: map)
            }
        }
        for i in group.groups.indices {
            remapBinaryRefs(in: &group.groups[i], using: map)
        }
    }

    private func remapBinaryRefs(in entry: inout KDBX.Entry, using map: [UInt32: Int]) {
        for i in entry.binaries.indices {
            guard case let .ref(id) = entry.binaries[i].value else { continue }
            // A ref whose ID isn't in the map was dangling on disk; leave
            // it as-is so KDBXContent.validate() still flags it (the index
            // will exceed the pool count).
            if let index = map[id] {
                entry.binaries[i] = .init(key: entry.binaries[i].key, value: .ref(UInt32(index)))
            }
        }
    }

    // MARK: Parse <XML Tag> helpers

    func parseKeepassFile(_ node: Node) throws(Error) -> (KDBX.Meta, KDBX.Root) {
        var meta: KDBX.Meta?
        var root: KDBX.Root?

        for child in node.children {
            switch child.name {
            case "Meta":
                meta = try parseMeta(child)

            case "Root":
                root = try parseRoot(child)

            default:
                record("Unexpected element: \(child.fullyQualifiedName)")
            }
        }

        guard let meta, let root else {
            throw .corrupted(reason: "Missing Meta or Root element in \(node.fullyQualifiedName)")
        }

        return (meta, root)
    }

    func parseMeta(_ node: Node) throws(Error) -> KDBX.Meta {
        // Accumulate parsed values into locals and assemble the Meta
        // in a single `init(...)` call at the end. Direct field
        // mutation (`meta.databaseName = ...`) would fire the field's
        // `didSet` observer and clobber `settingsChanged` with `Date()`,
        // losing the on-disk timestamp. The initial assignments inside
        // `KDBX.Meta.init(...)` don't fire didSet, so this is the only
        // path that preserves parsed timestamps verbatim.
        var generator: String?
        var headerHash: String?
        var settingsChanged: Date?
        var databaseName: String?
        var databaseNameChanged: Date?
        var databaseDescription: String?
        var databaseDescriptionChanged: Date?
        var defaultUserName: String?
        var defaultUserNameChanged: Date?
        var maintenanceHistoryDays: UInt32?
        var color: KDBX.Color?
        var masterKeyChanged: Date?
        var masterKeyChangeRec: KDBX.ValueOrNever<UInt64>?
        var masterKeyChangeForce: KDBX.ValueOrNever<UInt64>?
        var masterKeyChangeForceOnce: Bool?
        var memoryProtection: KDBX.MemoryProtectionConfig?
        var customIcons: [KDBX.CustomIcon] = []
        var recycleBinEnabled: Bool?
        var recycleBinUUID: UUID?
        var recycleBinChanged: Date?
        var entryTemplatesGroup: UUID?
        var entryTemplatesGroupChanged: Date?
        var historyMaxItems: KDBX.ValueOrUnlimited<UInt32>?
        var historyMaxSize: KDBX.ValueOrUnlimited<UInt64>?
        var lastSelectedGroup: UUID?
        var lastTopVisibleGroup: UUID?
        var customData: [KDBX.CustomDataWithTimes] = []

        for child in node.children {
            switch child.name {
            case "Generator":
                generator = text(in: child)

            case "HeaderHash":
                headerHash = text(in: child)

            case "SettingsChanged":
                if let stringValue = text(in: child) {
                    settingsChanged = try parseDate(stringValue, node: child)
                }

            case "DatabaseName":
                databaseName = text(in: child)

            case "DatabaseNameChanged":
                if let stringValue = text(in: child) {
                    databaseNameChanged = try parseDate(stringValue, node: child)
                }

            case "DatabaseDescription":
                databaseDescription = text(in: child)

            case "DatabaseDescriptionChanged":
                if let stringValue = text(in: child) {
                    databaseDescriptionChanged = try parseDate(stringValue, node: child)
                }

            case "DefaultUserName":
                defaultUserName = text(in: child)

            case "DefaultUserNameChanged":
                if let stringValue = text(in: child) {
                    defaultUserNameChanged = try parseDate(stringValue, node: child)
                }

            case "MaintenanceHistoryDays":
                if let stringValue = text(in: child) {
                    maintenanceHistoryDays = parseLenientUnsigned(stringValue, node: child)
                }

            case "Color":
                // Empty string is allowed as a special "default" color
                let stringValue = text(in: child) ?? ""
                color = try parseColor(stringValue, node: child)

            case "MasterKeyChanged":
                if let stringValue = text(in: child) {
                    masterKeyChanged = try parseDate(stringValue, node: child)
                }

            case "MasterKeyChangeRec":
                if let stringValue = text(in: child) {
                    masterKeyChangeRec = try parseValueOrNever(stringValue, node: child)
                }

            case "MasterKeyChangeForce":
                if let stringValue = text(in: child) {
                    masterKeyChangeForce = try parseValueOrNever(stringValue, node: child)
                }

            case "MasterKeyChangeForceOnce":
                if let stringValue = text(in: child) {
                    masterKeyChangeForceOnce = try parseBool(stringValue, node: child)
                }

            case "MemoryProtection":
                memoryProtection = try parseMemoryProtection(child)

            case "CustomIcons":
                customIcons = try parseCustomIconList(child)

            case "RecycleBinEnabled":
                if let stringValue = text(in: child) {
                    recycleBinEnabled = try parseBool(stringValue, node: child)
                }

            case "RecycleBinUUID":
                if let stringValue = text(in: child) {
                    recycleBinUUID = try parseUUID(stringValue, node: child)
                }

            case "RecycleBinChanged":
                if let stringValue = text(in: child) {
                    recycleBinChanged = try parseDate(stringValue, node: child)
                }

            case "EntryTemplatesGroup":
                if let stringValue = text(in: child) {
                    entryTemplatesGroup = try parseUUID(stringValue, node: node)
                }

            case "EntryTemplatesGroupChanged":
                if let stringValue = text(in: child) {
                    entryTemplatesGroupChanged = try parseDate(stringValue, node: node)
                }

            case "HistoryMaxItems":
                if let stringValue = text(in: child) {
                    historyMaxItems = try parseValueOrUnlimited(stringValue, node: node)
                }

            case "HistoryMaxSize":
                if let stringValue = text(in: child) {
                    historyMaxSize = try parseValueOrUnlimited(stringValue, node: node)
                }

            case "LastSelectedGroup":
                if let stringValue = text(in: child) {
                    lastSelectedGroup = try parseUUID(stringValue, node: node)
                }

            case "LastTopVisibleGroup":
                if let stringValue = text(in: child) {
                    lastTopVisibleGroup = try parseUUID(stringValue, node: node)
                }

            case "CustomData":
                customData = try parseCustomDataWithTimesList(child)

            case "Binaries":
                // KDBX 3.x inline binary pool. KDBX 4 writers don't emit
                // this — binaries live in the inner header pool — so any
                // 4.x file reaching this branch is either hand-crafted or
                // a 3.x-flavoured edit. Either way the schema is the
                // same: harvest into `collectedInlineBinaries` and let
                // the caller decide what to do with the pool.
                try parseInlineBinariesPool(child)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return KDBX.Meta(
            generator: generator,
            headerHash: headerHash,
            settingsChanged: settingsChanged,
            databaseName: databaseName,
            databaseNameChanged: databaseNameChanged,
            databaseDescription: databaseDescription,
            databaseDescriptionChanged: databaseDescriptionChanged,
            defaultUserName: defaultUserName,
            defaultUserNameChanged: defaultUserNameChanged,
            maintenanceHistoryDays: maintenanceHistoryDays,
            color: color,
            masterKeyChanged: masterKeyChanged,
            masterKeyChangeRec: masterKeyChangeRec,
            masterKeyChangeForce: masterKeyChangeForce,
            masterKeyChangeForceOnce: masterKeyChangeForceOnce,
            memoryProtection: memoryProtection,
            customIcons: customIcons,
            recycleBinEnabled: recycleBinEnabled,
            recycleBinUUID: recycleBinUUID,
            recycleBinChanged: recycleBinChanged,
            entryTemplatesGroup: entryTemplatesGroup,
            entryTemplatesGroupChanged: entryTemplatesGroupChanged,
            historyMaxItems: historyMaxItems,
            historyMaxSize: historyMaxSize,
            lastSelectedGroup: lastSelectedGroup,
            lastTopVisibleGroup: lastTopVisibleGroup,
            customData: customData
        )
    }

    func parseRoot(_ node: Node) throws(Error) -> KDBX.Root {
        var group: KDBX.Group?
        var deletedObjects: [KDBX.DeletedObject]?

        for child in node.children {
            switch child.name {
            case "Group":
                group = try parseGroup(child)

            case "DeletedObjects":
                deletedObjects = try parseDeletedObjects(child)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        guard let group else {
            throw .corrupted(reason: "Missing Group element in \(node.fullyQualifiedName)")
        }

        return .init(group: group, deletedObjects: deletedObjects ?? [])
    }

    func parseMemoryProtection(_ node: Node) throws(Error) -> KDBX.MemoryProtectionConfig {
        var memoryProtection = KDBX.MemoryProtectionConfig()

        for child in node.children {
            switch child.name {
            case "ProtectTitle":
                if let stringValue = text(in: child) {
                    memoryProtection.protectTitle = try parseBool(stringValue, node: child)
                }
            case "ProtectUserName":
                if let stringValue = text(in: child) {
                    memoryProtection.protectUserName = try parseBool(stringValue, node: child)
                }
            case "ProtectPassword":
                if let stringValue = text(in: child) {
                    memoryProtection.protectPassword = try parseBool(stringValue, node: child)
                }
            case "ProtectURL":
                if let stringValue = text(in: child) {
                    memoryProtection.protectURL = try parseBool(stringValue, node: child)
                }
            case "ProtectNotes":
                if let stringValue = text(in: child) {
                    memoryProtection.protectNotes = try parseBool(stringValue, node: child)
                }
            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return memoryProtection
    }

    func parseCustomIconList(_ node: Node) throws(Error) -> [KDBX.CustomIcon] {
        var customIcons: [KDBX.CustomIcon] = []

        for itemNode in node.children {
            guard itemNode.name == "Icon" else {
                record("Unexpected element \(itemNode.fullyQualifiedName)")
                continue
            }

            let customIcon = try parseCustomIcon(itemNode)
            customIcons.append(customIcon)
        }

        return customIcons
    }

    func parseCustomIcon(_ node: Node) throws(Error) -> KDBX.CustomIcon {
        var uuid: UUID?
        var data: Data?
        var name: String?
        var lastModificationTime: Date?

        for child in node.children {
            switch child.name {
            case "UUID":
                if let stringValue = text(in: child) {
                    uuid = try parseUUID(stringValue, node: node)
                }

            case "Data":
                if let stringValue = text(in: child) {
                    guard let decodedData = Data(base64Encoded: stringValue) else {
                        throw .corrupted(reason: "Failed to parse base64 data in \(child.fullyQualifiedName)")
                    }
                    data = decodedData
                } else {
                    data = Data()
                }

            case "Name":
                name = text(in: child)

            case "LastModificationTime":
                if let stringValue = text(in: child) {
                    lastModificationTime = try parseDate(stringValue, node: node)
                }

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        guard let uuid, let data else {
            throw .corrupted(reason: "Missing UUID or Data in CustomIcon in \(node.fullyQualifiedName)")
        }

        return .init(uuid: uuid, data: data, name: name, lastModificationTime: lastModificationTime)
    }

    func parseCustomDataItemList(_ node: Node) throws(Error) -> [KDBX.CustomDataItem] {
        var customData: [KDBX.CustomDataItem] = []

        for itemNode in node.children {
            guard itemNode.name == "Item" else {
                record("Unexpected element \(itemNode.fullyQualifiedName)")
                continue
            }

            var key: String?
            var value: String?

            for child in itemNode.children {
                switch child.name {
                case "Key":
                    key = text(in: child) ?? ""
                case "Value":
                    value = text(in: child) ?? ""
                default:
                    record("Unexpected element \(child.fullyQualifiedName)")
                }
            }

            guard let key, let value else {
                record("Missing Key or Value node in CustomDataWithTimes in \(itemNode.fullyQualifiedName)")
                continue
            }

            customData.append(.init(key: key, value: value))
        }

        return customData
    }

    func parseCustomDataWithTimesList(_ node: Node) throws(Error) -> [KDBX.CustomDataWithTimes] {
        var customData: [KDBX.CustomDataWithTimes] = []

        for itemNode in node.children {
            guard itemNode.name == "Item" else {
                record("Unexpected element \(itemNode.fullyQualifiedName)")
                continue
            }

            var key: String?
            var value: String?
            var lastModificationTime: Date?

            for child in itemNode.children {
                switch child.name {
                case "Key":
                    key = text(in: child) ?? ""
                case "Value":
                    value = text(in: child) ?? ""
                case "LastModificationTime":
                    if let stringValue = text(in: child) {
                        lastModificationTime = try parseDate(stringValue, node: child)
                    }
                default:
                    record("Unexpected element \(child.fullyQualifiedName)")
                }
            }

            guard let key, let value else {
                record("Missing Key or Value node in CustomDataWithTimes in \(itemNode.fullyQualifiedName)")
                continue
            }

            customData.append(.init(key: key, value: value, lastModificationTime: lastModificationTime))
        }

        return customData
    }

    /// Hard cap on nested `<Group>` depth. Bounds stack usage in the
    /// recursive walk against pathological / crafted inputs. 100 levels of
    /// nested groups is absurd in any real vault (KeePass's own UI starts to
    /// struggle past two-digit nesting), so anyone hitting this is either
    /// corrupt or hostile.
    ///
    /// Settable so tests can lower it; production callers use the default.
    /// The XML parser itself is recursive-descent with no explicit cap, so
    /// a pathologically deep document would blow the thread stack before
    /// reaching this layer. In practice 100 levels is well under either
    /// bound and well past anything a real vault produces.
    var maxGroupNestingDepth = 100

    /// Same idea as ``maxGroupNestingDepth`` for the Entry → History →
    /// Entry recursion. History is flat in any real vault (KeePass never
    /// nests history inside history entries), so even single-digit depth
    /// only occurs in corrupt or hostile input — but each `parseEntry`
    /// frame is heavy, and ~500 of them can blow a 512 KiB secondary-
    /// thread stack before the XML layer's own 1024-element depth cap
    /// saves us.
    var maxHistoryNestingDepth = 8

    func parseGroup(_ node: Node, depth: Int = 0) throws(Error) -> KDBX.Group {
        if depth >= maxGroupNestingDepth {
            throw .corrupted(reason: "Group nesting exceeds \(maxGroupNestingDepth) levels in \(node.fullyQualifiedName)")
        }
        var group = KDBX.Group(uuid: UUID(), iconID: 0, tags: [], customData: [], entries: [], groups: [])

        for child in node.children {
            switch child.name {
            case "UUID":
                if let stringValue = text(in: child) {
                    group.uuid = try parseUUID(stringValue, node: child)
                }

            case "Name":
                group.name = text(in: child)

            case "Notes":
                group.notes = text(in: child)

            case "IconID":
                if let stringValue = text(in: child) {
                    group.iconID = try parseNumber(stringValue, node: node)
                }

            case "CustomIconUUID":
                if let stringValue = text(in: child) {
                    group.customIconUUID = try parseUUID(stringValue, node: child)
                }

            case "Times":
                group.times = try parseTimes(child)

            case "IsExpanded":
                if let stringValue = text(in: child) {
                    group.isExpanded = try parseBool(stringValue, node: child)
                }

            case "DefaultAutoTypeSequence":
                group.defaultAutoTypeSequence = text(in: child)

            case "EnableAutoType":
                group.enableAutoType = try parseNullableBoolEx(child)

            case "EnableSearching":
                group.enableSearching = try parseNullableBoolEx(child)

            case "LastTopVisibleEntry":
                if let stringValue = text(in: child) {
                    group.lastTopVisibleEntry = try parseUUID(stringValue, node: node)
                }

            case "PreviousParentGroup":
                if let stringValue = text(in: child) {
                    group.previousParentGroup = try parseUUID(stringValue, node: node)
                }

            case "Tags":
                group.tags = try parseTags(child)

            case "CustomData":
                group.customData = try parseCustomDataItemList(child)

            case "Entry":
                let entry = try parseEntry(child)
                group.entries.append(entry)

            case "Group":
                let subGroup = try parseGroup(child, depth: depth + 1)
                group.groups.append(subGroup)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return group
    }

    func parseTimes(_ node: Node) throws(Error) -> KDBX.Times {
        var times = KDBX.Times()

        for child in node.children {
            switch child.name {
            case "CreationTime":
                if let stringValue = text(in: child) {
                    times.creationTime = try parseDate(stringValue, node: child)
                }

            case "LastModificationTime":
                if let stringValue = text(in: child) {
                    times.lastModificationTime = try parseDate(stringValue, node: child)
                }

            case "LastAccessTime":
                if let stringValue = text(in: child) {
                    times.lastAccessTime = try parseDate(stringValue, node: child)
                }

            case "ExpiryTime":
                if let stringValue = text(in: child) {
                    times.expiryTime = try parseDate(stringValue, node: child)
                }

            case "Expires":
                if let stringValue = text(in: child) {
                    times.expires = try parseBool(stringValue, node: child)
                }

            case "UsageCount":
                if let stringValue = text(in: child) {
                    times.usageCount = parseLenientUnsigned(stringValue, node: node)
                }

            case "LocationChanged":
                if let stringValue = text(in: child) {
                    times.locationChanged = try parseDate(stringValue, node: node)
                }

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return times
    }

    func parseNullableBoolEx(_ node: Node) throws(Error) -> KDBX.NullableBoolEx? {
        guard let stringValue = text(in: node) else {
            return nil
        }

        switch stringValue {
        case "Null", "null":
            return .null
        case "False", "false":
            return .value(false)
        case "True", "true":
            return .value(true)
        default:
            throw .corrupted(reason: "Failed to parse NullableBoolEx value \(stringValue) in \(node.fullyQualifiedName)")
        }
    }

    func parseTags(_ node: Node) throws(Error) -> [String] {
        guard let stringValue = text(in: node) else {
            return []
        }

        // The KDBX 4.1 XSD documents `;` as the tag separator, but
        // KeePassXC writes tags comma-separated and KeePass 2 (.NET)
        // accepts both `;` and `,` on input. Split on either so we
        // round-trip with both clients.
        //
        // Trailing/empty segments ("a;", ";;b") produce empty strings via
        // `components(separatedBy:)` — drop them since an empty tag has
        // no meaning.
        return stringValue
            .components(separatedBy: CharacterSet(charactersIn: ";,"))
            .filter { !$0.isEmpty }
    }

    func parseEntry(_ node: Node, historyDepth: Int = 0) throws(Error) -> KDBX.Entry {
        if historyDepth > maxHistoryNestingDepth {
            throw .corrupted(reason: "Entry history nesting exceeds \(maxHistoryNestingDepth) levels in \(node.fullyQualifiedName)")
        }
        var entry = KDBX.Entry(uuid: UUID(), iconID: 0, tags: [], strings: [], binaries: [], customData: [], history: [])

        for child in node.children {
            switch child.name {
            case "UUID":
                if let stringValue = text(in: child) {
                    entry.uuid = try parseUUID(stringValue, node: child)
                }

            case "IconID":
                if let stringValue = text(in: child) {
                    entry.iconID = try parseNumber(stringValue, node: child)
                }

            case "CustomIconUUID":
                if let stringValue = text(in: child) {
                    entry.customIconUUID = try parseUUID(stringValue, node: child)
                }

            case "ForegroundColor":
                // Empty string is allowed as a special "default" color
                let stringValue = text(in: child) ?? ""
                entry.foregroundColor = try parseColor(stringValue, node: child)

            case "BackgroundColor":
                // Empty string is allowed as a special "default" color
                let stringValue = text(in: child) ?? ""
                entry.backgroundColor = try parseColor(stringValue, node: child)

            case "OverrideURL":
                entry.overrideURL = text(in: child)

            case "QualityCheck":
                if let stringValue = text(in: child) {
                    entry.qualityCheck = try parseBool(stringValue, node: child)
                }

            case "Tags":
                entry.tags = try parseTags(child)

            case "PreviousParentGroup":
                if let stringValue = text(in: child) {
                    entry.previousParentGroup = try parseUUID(stringValue, node: node)
                }

            case "Times":
                entry.times = try parseTimes(child)

            case "String":
                let protectedString = try parseProtectedString(child)
                entry.strings.append(protectedString)

            case "Binary":
                let protectedBinary = try parseProtectedBinary(child)
                entry.binaries.append(protectedBinary)

            case "AutoType":
                entry.autoType = try parseAutoType(child)

            case "CustomData":
                entry.customData = try parseCustomDataItemList(child)

            case "History":
                entry.history = try parseEntryList(child, historyDepth: historyDepth + 1)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return entry
    }

    func parseEntryList(_ node: Node, historyDepth: Int = 0) throws(Error) -> [KDBX.Entry] {
        var entries: [KDBX.Entry] = []

        for child in node.children {
            switch child.name {
            case "Entry":
                let entry = try parseEntry(child, historyDepth: historyDepth)
                entries.append(entry)
            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return entries
    }

    func parseProtectedString(_ node: Node) throws(Error) -> KDBX.ProtectedString {
        var key: String?
        var rawValue: String?
        var isProtected: Bool?
        var shouldProtectInMemory: Bool?

        for child in node.children {
            switch child.name {
            case "Key":
                // allow empty string, it happens in real documents
                key = text(in: child) ?? ""

            case "Value":
                rawValue = text(in: child)
                for (name, value) in child.attributes {
                    switch name {
                    case "Protected":
                        switch value {
                        case "True":
                            isProtected = true
                        case "False":
                            isProtected = false
                        default:
                            record("Unexpected attribute value '\(value)' in attribute \(name) in \(child.fullyQualifiedName)")
                        }

                    case "ProtectInMemory":
                        switch value {
                        case "True":
                            shouldProtectInMemory = true
                        case "False":
                            shouldProtectInMemory = false
                        default:
                            record("Unexpected attribute value '\(value)' in attribute \(name) in \(child.fullyQualifiedName)")
                        }

                    default:
                        record("Unexpected attribute '\(name)' in String in \(child.fullyQualifiedName)")
                    }
                }

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        guard let key else {
            throw .corrupted(reason: "Failed to parse ProtectedString, missing key in \(node.fullyQualifiedName)")
        }

        let value: KDBX.ProtectedString.Value
        if let isProtected, isProtected {
            if let rawValue {
                guard let data = Data(base64Encoded: rawValue) else {
                    throw .corrupted(reason: "Failed to parse base64 ProtectedData in \(node.fullyQualifiedName)")
                }
                // Lazy: record (ciphertext, current offset, shared source).
                // The plaintext is only materialized when a caller asks
                // via `.bytes` / `.withRevealedString`. Until then the
                // entry's password lives in memory as base64-decoded
                // ciphertext, which is useless without the inner key.
                value = .lazyInnerCipher(
                    ciphertext: data,
                    offset: cursor.position,
                    source: keystreamSource
                )
                // Advance the offset — the writer wrote these N bytes
                // of keystream linearly when it produced this node, so
                // the next protected node we encounter starts at this
                // new offset.
                cursor.advance(by: data.count)
            } else {
                value = .unprotected("")
            }
        } else if let shouldProtectInMemory, shouldProtectInMemory {
            // TODO: we are currently not protecting in memory
            record("Protect in memory not yet implemented in \(node.fullyQualifiedName)")
            value = .protectedInMemory(rawValue ?? "")
        } else {
            value = .regular(rawValue ?? "")
        }

        return .init(key: key, value: value)
    }

    func parseProtectedBinary(_ node: Node) throws(Error) -> KDBX.ProtectedBinary {
        var key: String?
        var rawValue: String?
        var ref: UInt32?
        var protected = false

        for child in node.children {
            switch child.name {
            case "Key":
                key = text(in: child)

            case "Value":
                rawValue = text(in: child)
                for (name, value) in child.attributes {
                    switch name {
                    case "Ref":
                        guard let refValue = UInt32(value) else {
                            throw .corrupted(reason: "Failed to parse Ref attribute: '\(value)'")
                        }
                        ref = refValue

                    case "Protected":
                        // Inline binaries in KDBX 3.1 (and any KDBX 4
                        // inline binary) can carry Protected="True"
                        // exactly like ProtectedString — same XSD
                        // shape. The flag has no meaning on a ref;
                        // for refs the pool entry's
                        // `shouldBeProtected` is the source of truth.
                        switch value.lowercased() {
                        case "true": protected = true
                        case "false": protected = false
                        default:
                            record("Unexpected Protected value '\(value)' in Binary in \(child.fullyQualifiedName)")
                        }

                    default:
                        record("Unexpected attribute '\(name)' in Binary in \(child.fullyQualifiedName)")
                    }
                }

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        guard let key else {
            throw .corrupted(reason: "Failed to parse ProtectedBinary, missing key in \(node.fullyQualifiedName)")
        }

        guard rawValue != nil || ref != nil else {
            throw .corrupted(reason: "Failed to parse ProtectedBinary, missing value or ref in \(node.fullyQualifiedName). Value=\(rawValue ?? "<nil>"); Ref=\(ref.map { String($0) } ?? "<nil>")")
        }

        let value: KDBX.ProtectedBinary.Value
        if let ref {
            value = .ref(ref)
        } else if let rawValue {
            guard let data = Data(base64Encoded: rawValue) else {
                throw .corrupted(reason: "Failed to parse base64 inline data in ProtectedBinary in \(node.fullyQualifiedName)")
            }
            if protected {
                // Protected inline binaries are XOR'd with the shared
                // inner keystream exactly like protected strings,
                // consuming it in document order (KeePass and KeePassXC
                // both do this). Decrypt eagerly — the model carries
                // inline bytes as plain Data — and advance the shared
                // cursor so every later protected value decrypts at the
                // right offset.
                let decrypted = keystreamSource.decrypt(ciphertext: data, at: cursor.position).toData()
                cursor.advance(by: data.count)
                value = .inline(decrypted, protected: true)
            } else {
                value = .inline(data, protected: false)
            }
        } else {
            // Unreachable while the guard above holds, but a parse path
            // never gets a trap primitive — corrupt input throws.
            throw .corrupted(reason: "ProtectedBinary in \(node.fullyQualifiedName) had neither Ref nor Value")
        }

        return .init(key: key, value: value)
    }

    func parseDeletedObject(_ node: Node) throws(Error) -> KDBX.DeletedObject {
        var uuid: UUID?
        var deletionTime: Date?

        for child in node.children {
            switch child.name {
            case "UUID":
                if let stringValue = text(in: child) {
                    uuid = try parseUUID(stringValue, node: node)
                }
            case "DeletionTime":
                if let stringValue = text(in: child) {
                    deletionTime = try parseDate(stringValue, node: child)
                }
            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        guard let uuid, let deletionTime else {
            throw .corrupted(reason: "Missing UUID or DeletionTime in DeletedObject in \(node.fullyQualifiedName)")
        }

        return .init(uuid: uuid, deletionTime: deletionTime)
    }

    func parseDeletedObjects(_ node: Node) throws(Error) -> [KDBX.DeletedObject] {
        var deletedObjects: [KDBX.DeletedObject] = []
        for child in node.children {
            switch child.name {
            case "DeletedObject":
                let deletedObject = try parseDeletedObject(child)
                deletedObjects.append(deletedObject)
            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }
        return deletedObjects
    }

    func parseAutoType(_ node: Node) throws(Error) -> KDBX.AutoType {
        var autotype = KDBX.AutoType()

        for child in node.children {
            switch child.name {
            case "Enabled":
                if let stringValue = text(in: child) {
                    autotype.enabled = try parseBool(stringValue, node: node)
                }

            case "DataTransferObfuscation":
                autotype.dataTransferObfuscation = try parseDataTransferObfuscation(child)

            case "DefaultSequence":
                autotype.defaultSequence = text(in: child)

            case "Association":
                let association = try parseAutoTypeAssociation(child)
                autotype.association.append(association)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return autotype
    }

    func parseAutoTypeAssociation(_ node: Node) throws(Error) -> KDBX.AutoType.Association {
        var window: String?
        var keyStrokeSequence: String?

        for child in node.children {
            switch child.name {
            case "Window":
                // XSD: `xs:string`. Empty content is valid (KeePass emits an
                // empty `<Window/>` and `<KeystrokeSequence/>` when the user
                // leaves the field blank — meaning "use parent default").
                // Distinguish "element present but empty" (→ "") from
                // "element missing" (→ nil → throw below).
                window = text(in: child) ?? ""

            case "KeystrokeSequence":
                keyStrokeSequence = text(in: child) ?? ""

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        guard let window, let keyStrokeSequence else {
            throw .corrupted(reason: "Mising Window or KeystrokeSequence in AutoType Association in \(node.fullyQualifiedName)")
        }

        return .init(window: window, keystrokeSequence: keyStrokeSequence)
    }

    func parseDataTransferObfuscation(_ node: Node) throws(Error) -> KDBX.AutoType.DataTransferObfuscation {
        guard let stringValue = text(in: node) else {
            throw .corrupted(reason: "Missing value in DataTransferObfuscation in \(node.fullyQualifiedName)")
        }

        let value: Int32 = try parseNumber(stringValue, node: node)

        guard let dtob = KDBX.AutoType.DataTransferObfuscation(rawValue: value) else {
            throw .corrupted(reason: "Unknown value for DataTransferObfuscation in \(node.fullyQualifiedName)")
        }

        return dtob
    }
}
