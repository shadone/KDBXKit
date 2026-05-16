//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Nodal

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

struct XMLDocumentReader {
    enum Error: Swift.Error {
        case corrupted(reason: String)
    }

    let document: Document

    var meta = KDBX.Meta()
    var root: KDBX.Root?

    /// Random-access keystream — the reader records each protected
    /// node's keystream offset instead of decrypting in line.
    let keystreamSource: KeystreamSource

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

    init(xmlDocument: String, keystreamSource: KeystreamSource) {
        document = try! Document(string: xmlDocument)
        self.keystreamSource = keystreamSource
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
        guard
            let secondsSinceDotnetEpoch = Data(base64Encoded: string)?.asInt64LE()
        else {
            throw .corrupted(reason: "Failed to parse date '\(string)' from \(node.fullyQualifiedName)")
        }

        return Date(secondsSinceDotNetEpoch: secondsSinceDotnetEpoch)
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
        guard let documentElement = document.documentElement else {
            throw .corrupted(reason: "Missig root element")
        }

        guard documentElement.name == "KeePassFile" else {
            throw .corrupted(reason: "Invalid root element: \(documentElement.name)")
        }

        let (meta, root) = try parseKeepassFile(documentElement)
        return .init(meta: meta, root: root)
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
        var meta = KDBX.Meta()

        for child in node.children {
            switch child.name {
            case "Generator":
                meta.generator = text(in: child)

            case "HeaderHash":
                meta.headerHash = text(in: child)

            case "SettingsChanged":
                if let stringValue = text(in: child) {
                    meta.settingsChanged = try parseDate(stringValue, node: child)
                }

            case "DatabaseName":
                meta.databaseName = text(in: child)

            case "DatabaseNameChanged":
                if let stringValue = text(in: child) {
                    meta.databaseNameChanged = try parseDate(stringValue, node: child)
                }

            case "DatabaseDescription":
                meta.databaseDescription = text(in: child)

            case "DatabaseDescriptionChanged":
                if let stringValue = text(in: child) {
                    meta.databaseDescriptionChanged = try parseDate(stringValue, node: child)
                }
            case "DefaultUserName":
                meta.defaultUserName = text(in: child)

            case "DefaultUserNameChanged":
                if let stringValue = text(in: child) {
                    meta.defaultUserNameChanged = try parseDate(stringValue, node: child)
                }

            case "MaintenanceHistoryDays":
                if let stringValue = text(in: child) {
                    meta.maintenanceHistoryDays = parseLenientUnsigned(stringValue, node: child)
                }

            case "Color":
                // Empty string is allowed as a special "default" color
                let stringValue = text(in: child) ?? ""
                meta.color = try parseColor(stringValue, node: child)

            case "MasterKeyChanged":
                if let stringValue = text(in: child) {
                    meta.masterKeyChanged = try parseDate(stringValue, node: child)
                }

            case "MasterKeyChangeRec":
                if let stringValue = text(in: child) {
                    meta.masterKeyChangeRec = try parseValueOrNever(stringValue, node: child)
                }

            case "MasterKeyChangeForce":
                if let stringValue = text(in: child) {
                    meta.masterKeyChangeForce = try parseValueOrNever(stringValue, node: child)
                }

            case "MasterKeyChangeForceOnce":
                if let stringValue = text(in: child) {
                    meta.masterKeyChangeForceOnce = try parseBool(stringValue, node: child)
                }

            case "MemoryProtection":
                meta.memoryProtection = try parseMemoryProtection(child)

            case "CustomIcons":
                meta.customIcons = try parseCustomIconList(child)

            case "RecycleBinEnabled":
                if let stringValue = text(in: child) {
                    meta.recycleBinEnabled = try parseBool(stringValue, node: child)
                }

            case "RecycleBinUUID":
                if let stringValue = text(in: child) {
                    meta.recycleBinUUID = try parseUUID(stringValue, node: child)
                }

            case "RecycleBinChanged":
                if let stringValue = text(in: child) {
                    meta.recycleBinChanged = try parseDate(stringValue, node: child)
                }

            case "EntryTemplatesGroup":
                if let stringValue = text(in: child) {
                    meta.entryTemplatesGroup = try parseUUID(stringValue, node: node)
                }

            case "EntryTemplatesGroupChanged":
                if let stringValue = text(in: child) {
                    meta.entryTemplatesGroupChanged = try parseDate(stringValue, node: node)
                }

            case "HistoryMaxItems":
                if let stringValue = text(in: child) {
                    meta.historyMaxItems = try parseValueOrUnlimited(stringValue, node: node)
                }

            case "HistoryMaxSize":
                if let stringValue = text(in: child) {
                    meta.historyMaxSize = try parseValueOrUnlimited(stringValue, node: node)
                }

            case "LastSelectedGroup":
                if let stringValue = text(in: child) {
                    meta.lastSelectedGroup = try parseUUID(stringValue, node: node)
                }

            case "LastTopVisibleGroup":
                if let stringValue = text(in: child) {
                    meta.lastTopVisibleGroup = try parseUUID(stringValue, node: node)
                }

            case "CustomData":
                meta.customData = try parseCustomDataWithTimesList(child)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return meta
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
    /// Note that the underlying XML parser (Nodal) has its own recursion
    /// limit which is platform-dependent and likely lower than wide ints —
    /// in practice a malicious input is more likely to be rejected by the
    /// XML layer first.
    var maxGroupNestingDepth = 100

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

    func parseEntry(_ node: Node) throws(Error) -> KDBX.Entry {
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
                entry.history = try parseEntryList(child)

            default:
                record("Unexpected element \(child.fullyQualifiedName)")
            }
        }

        return entry
    }

    func parseEntryList(_ node: Node) throws(Error) -> [KDBX.Entry] {
        var entries: [KDBX.Entry] = []

        for child in node.children {
            switch child.name {
            case "Entry":
                let entry = try parseEntry(child)
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
            value = .inline(data)
        } else {
            preconditionFailure()
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
