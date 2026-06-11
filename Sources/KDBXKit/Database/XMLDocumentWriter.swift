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
///          - XML document.             <<- writes XML document
/// ```
struct XMLDocumentWriter {
    enum Error: Swift.Error {
        case unknown(reason: String)
        /// When writing to a fixed length stream, there is no place to write.
        case unexpectedEOF
    }

    let outputStream: OutputStream
    let encryptor: any Encryptable

    init(to outputStream: OutputStream, encryptor: any Encryptable) {
        self.outputStream = outputStream
        self.encryptor = encryptor
    }

    private func write(_ value: some FixedWidthInteger) throws(Error) {
        try write(value.toDataLittleEndian())
    }

    private func write(_ data: Data) throws(Error) {
        do {
            try outputStream.write(data: data)
        } catch {
            switch error {
            case let .streamError(error):
                let description = error?.localizedDescription ?? "nil"
                throw .unknown(reason: "Write failed: \(description)")

            case .unexpectedEOF:
                throw .unexpectedEOF
            }
        }
    }

    private func encode(_ value: Date) -> String {
        value.secondsSinceDotNetEpoch
            .toDataLittleEndian()
            .base64EncodedString()
    }

    private func encode(_ value: some FixedWidthInteger) -> String {
        String(value)
    }

    private func encode(_ value: KDBX.Color) -> String {
        value.description
    }

    private func encode(_ value: Bool) -> String {
        value ? "True" : "False"
    }

    private func encode(_ value: UUID) -> String {
        value.toUInt128()
            .toDataLittleEndian()
            .base64EncodedString()
    }

    private func encode(_ value: Data) -> String {
        value.base64EncodedString()
    }

    private func encode(_ value: KDBX.ValueOrNever<some FixedWidthInteger>) -> String {
        switch value {
        case .never:
            return "-1"
        case let .value(value):
            return String(value)
        }
    }

    private func encode(_ value: KDBX.ValueOrUnlimited<some FixedWidthInteger>) -> String {
        switch value {
        case .unlimited:
            return "-1"
        case let .value(value):
            return String(value)
        }
    }

    private func encode(_ value: KDBX.NullableBoolEx) -> String {
        switch value {
        case .null:
            return "Null"
        case let .value(b):
            return b ? "True" : "False"
        }
    }

    private func write(_ meta: KDBX.Meta, to node: Node) {
        if let generator = meta.generator {
            node.addElement("Generator").addText(generator)
        }
        // HeaderHash is a KDBX-3-only integrity field (hash of the outer
        // header). This writer only ever emits KDBX 4 framing with fresh
        // salts, so any inherited hash is stale — KeePass omits it in v4
        // and we do too rather than assert incorrect data.
        if let settingsChanged = meta.settingsChanged {
            node.addElement("SettingsChanged").addText(encode(settingsChanged))
        }
        if let databaseName = meta.databaseName {
            node.addElement("DatabaseName").addText(databaseName)
        }
        if let databaseNameChanged = meta.databaseNameChanged {
            node.addElement("DatabaseNameChanged").addText(encode(databaseNameChanged))
        }
        if let databaseDescription = meta.databaseDescription {
            node.addElement("DatabaseDescription").addText(databaseDescription)
        }
        if let databaseDescriptionChanged = meta.databaseDescriptionChanged {
            node.addElement("DatabaseDescriptionChanged").addText(encode(databaseDescriptionChanged))
        }
        if let defaultUserName = meta.defaultUserName {
            node.addElement("DefaultUserName").addText(defaultUserName)
        }
        if let defaultUserNameChanged = meta.defaultUserNameChanged {
            node.addElement("DefaultUserNameChanged").addText(encode(defaultUserNameChanged))
        }
        if let maintenanceHistoryDays = meta.maintenanceHistoryDays {
            node.addElement("MaintenanceHistoryDays").addText(encode(maintenanceHistoryDays))
        }
        if let color = meta.color {
            node.addElement("Color").addText(encode(color))
        }
        if let masterKeyChanged = meta.masterKeyChanged {
            node.addElement("MasterKeyChanged").addText(encode(masterKeyChanged))
        }
        if let masterKeyChangeRec = meta.masterKeyChangeRec {
            node.addElement("MasterKeyChangeRec").addText(encode(masterKeyChangeRec))
        }
        if let masterKeyChangeForce = meta.masterKeyChangeForce {
            node.addElement("MasterKeyChangeForce").addText(encode(masterKeyChangeForce))
        }
        if let masterKeyChangeForceOnce = meta.masterKeyChangeForceOnce {
            node.addElement("MasterKeyChangeForceOnce").addText(encode(masterKeyChangeForceOnce))
        }
        if let memoryProtection = meta.memoryProtection {
            let memoryProtectionNode = node.addElement("MemoryProtection")
            write(memoryProtection, to: memoryProtectionNode)
        }
        if !meta.customIcons.isEmpty {
            let customIconNode = node.addElement("CustomIcons")
            for customIcon in meta.customIcons {
                let iconNode = customIconNode.addElement("Icon")
                write(customIcon, to: iconNode)
            }
        }
        if let recycleBinEnabled = meta.recycleBinEnabled {
            node.addElement("RecycleBinEnabled").addText(encode(recycleBinEnabled))
        }
        if let recycleBinUUID = meta.recycleBinUUID {
            node.addElement("RecycleBinUUID").addText(encode(recycleBinUUID))
        }
        if let recycleBinChanged = meta.recycleBinChanged {
            node.addElement("RecycleBinChanged").addText(encode(recycleBinChanged))
        }
        if let entryTemplatesGroup = meta.entryTemplatesGroup {
            node.addElement("EntryTemplatesGroup").addText(encode(entryTemplatesGroup))
        }
        if let entryTemplatesGroupChanged = meta.entryTemplatesGroupChanged {
            node.addElement("EntryTemplatesGroupChanged").addText(encode(entryTemplatesGroupChanged))
        }
        if let historyMaxItems = meta.historyMaxItems {
            node.addElement("HistoryMaxItems").addText(encode(historyMaxItems))
        }
        if let historyMaxSize = meta.historyMaxSize {
            node.addElement("HistoryMaxSize").addText(encode(historyMaxSize))
        }
        if let lastSelectedGroup = meta.lastSelectedGroup {
            node.addElement("LastSelectedGroup").addText(encode(lastSelectedGroup))
        }
        if let lastTopVisibleGroup = meta.lastTopVisibleGroup {
            node.addElement("LastTopVisibleGroup").addText(encode(lastTopVisibleGroup))
        }
        if !meta.customData.isEmpty {
            let customDataNode = node.addElement("CustomData")
            for customData in meta.customData {
                let itemNode = customDataNode.addElement("Item")
                write(customData, to: itemNode)
            }
        }
    }

    private func write(_ root: KDBX.Root, to node: Node) {
        let groupNode = node.addElement("Group")
        write(root.group, to: groupNode)

        if !root.deletedObjects.isEmpty {
            let deletedObjectsNode = node.addElement("DeletedObjects")
            for deletedObject in root.deletedObjects {
                let itemNode = deletedObjectsNode.addElement("DeletedObject")
                write(deletedObject, to: itemNode)
            }
        }
    }

    private func write(_ group: KDBX.Group, to node: Node) {
        node.addElement("UUID").addText(encode(group.uuid))
        if let name = group.name {
            node.addElement("Name").addText(name)
        }
        if let notes = group.notes {
            node.addElement("Notes").addText(notes)
        }
        node.addElement("IconID").addText(encode(group.iconID))
        if let customIconUUID = group.customIconUUID {
            node.addElement("CustomIconUUID").addText(encode(customIconUUID))
        }
        if let times = group.times {
            let timesNode = node.addElement("Times")
            write(times, to: timesNode)
        }
        if let isExpanded = group.isExpanded {
            node.addElement("IsExpanded").addText(encode(isExpanded))
        }
        if let defaultAutoTypeSequence = group.defaultAutoTypeSequence {
            node.addElement("DefaultAutoTypeSequence").addText(defaultAutoTypeSequence)
        }
        if let enableAutoType = group.enableAutoType {
            node.addElement("EnableAutoType").addText(encode(enableAutoType))
        }
        if let enableSearching = group.enableSearching {
            node.addElement("EnableSearching").addText(encode(enableSearching))
        }
        if let lastTopVisibleEntry = group.lastTopVisibleEntry {
            node.addElement("LastTopVisibleEntry").addText(encode(lastTopVisibleEntry))
        }
        if let previousParentGroup = group.previousParentGroup {
            node.addElement("PreviousParentGroup").addText(encode(previousParentGroup))
        }
        if !group.tags.isEmpty {
            // KeePassXC writes `,`-separated; the KDBX 4.1 XSD nominally
            // says `;`, but both KeePass 2 (.NET) and KeePassXC accept
            // either on read. Emit `,` to match KeePassXC's preferred form.
            node.addElement("Tags").addText(group.tags.joined(separator: ","))
        }
        if !group.customData.isEmpty {
            let customDataNode = node.addElement("CustomData")
            for customData in group.customData {
                let itemNode = customDataNode.addElement("Item")
                write(customData, to: itemNode)
            }
        }
        if !group.entries.isEmpty {
            for entry in group.entries {
                let entryNode = node.addElement("Entry")
                write(entry, to: entryNode)
            }
        }
        if !group.groups.isEmpty {
            for subgroup in group.groups {
                let subgroupNode = node.addElement("Group")
                write(subgroup, to: subgroupNode)
            }
        }
    }

    private func write(_ entry: KDBX.Entry, to node: Node) {
        node.addElement("UUID").addText(encode(entry.uuid))
        node.addElement("IconID").addText(encode(entry.iconID))
        if let customIconUUID = entry.customIconUUID {
            node.addElement("CustomIconUUID").addText(encode(customIconUUID))
        }
        if let foregroundColor = entry.foregroundColor {
            node.addElement("ForegroundColor").addText(encode(foregroundColor))
        }
        if let backgroundColor = entry.backgroundColor {
            node.addElement("BackgroundColor").addText(encode(backgroundColor))
        }
        if let overrideURL = entry.overrideURL {
            node.addElement("OverrideURL").addText(overrideURL)
        }
        if let qualityCheck = entry.qualityCheck {
            node.addElement("QualityCheck").addText(encode(qualityCheck))
        }
        if !entry.tags.isEmpty {
            // KeePassXC writes `,`-separated; the KDBX 4.1 XSD nominally
            // says `;`, but both KeePass 2 (.NET) and KeePassXC accept
            // either on read. Emit `,` to match KeePassXC's preferred form.
            node.addElement("Tags").addText(entry.tags.joined(separator: ","))
        }
        if let previousParentGroup = entry.previousParentGroup {
            node.addElement("PreviousParentGroup").addText(encode(previousParentGroup))
        }
        if let times = entry.times {
            let timesNode = node.addElement("Times")
            write(times, to: timesNode)
        }
        if !entry.strings.isEmpty {
            for protectedString in entry.strings {
                let stringNode = node.addElement("String")
                write(protectedString, to: stringNode)
            }
        }
        if !entry.binaries.isEmpty {
            for protectedBinary in entry.binaries {
                let binaryNode = node.addElement("Binary")
                write(protectedBinary, to: binaryNode)
            }
        }
        if let autoType = entry.autoType {
            let autoTypeNode = node.addElement("AutoType")
            write(autoType, to: autoTypeNode)
        }
        if !entry.customData.isEmpty {
            let customDataNode = node.addElement("CustomData")
            for customData in entry.customData {
                let itemNode = customDataNode.addElement("Item")
                write(customData, to: itemNode)
            }
        }
        if !entry.history.isEmpty {
            let historyNode = node.addElement("History")
            for historicalEntry in entry.history {
                let entryNode = historyNode.addElement("Entry")
                write(historicalEntry, to: entryNode)
            }
        }
    }

    private func write(_ protectedString: KDBX.ProtectedString, to node: Node) {
        node.addElement("Key").addText(protectedString.key)

        let valueNode = node.addElement("Value")
        switch protectedString.value {
        case let .regular(bytes):
            // Cleartext XML — non-secret. Materialize a transient String just
            // for the XML text node; XMLDocumentWriter takes String anyway.
            bytes.withRevealedString { valueNode.addText($0) }

        case .unprotected, .lazyInnerCipher:
            // Both cases serialize the same way on disk — as base64
            // `Protected="True"`. For `.unprotected` the bytes are
            // already plaintext in SecureBytes; for `.lazyInnerCipher`
            // we have to decrypt with the *reader's* keystream source
            // and re-encrypt with the writer's fresh `encryptor`,
            // because the inner key regenerates per write.
            //
            // `.bytes` handles both — for `.lazyInnerCipher` it runs
            // the lazy decrypt and returns a fresh SecureBytes that
            // zero-deinits as soon as the let binding drops it.
            let bytes = protectedString.value.bytes
            let encrypted = bytes.withUnsafeBytes { ptr in
                Data(encryptor.encrypt(Array(ptr.bindMemory(to: UInt8.self))))
            }
            valueNode.addText(encode(encrypted))
            valueNode.attributes = [
                (name: "Protected", value: "True"),
            ]

        case let .protectedInMemory(bytes):
            bytes.withRevealedString { valueNode.addText($0) }
            valueNode.attributes = [
                (name: "ProtectInMemory", value: "True"),
            ]
        }
    }

    private func write(_ protectedBinary: KDBX.ProtectedBinary, to node: Node) {
        node.addElement("Key").addText(protectedBinary.key)

        let valueNode = node.addElement("Value")
        switch protectedBinary.value {
        case let .ref(ref):
            valueNode.attributes = [
                (name: "Ref", value: String(ref)),
            ]

        case let .inline(data, protected):
            if protected {
                // Same inner-stream treatment as protected strings:
                // Protected="True" means the value is XOR'd with the
                // shared keystream, consumed in document order — KeePass
                // and KeePassXC XOR-decrypt this value on open, so
                // emitting raw bytes here would hand them ciphertext AND
                // shift every later protected value's offset.
                let encrypted = Data(encryptor.encrypt(Array(data)))
                valueNode.addText(encode(encrypted))
                valueNode.attributes = [
                    (name: "Protected", value: "True"),
                ]
            } else {
                valueNode.addText(encode(data))
            }
        }
    }

    private func write(_ times: KDBX.Times, to node: Node) {
        if let creationTime = times.creationTime {
            node.addElement("CreationTime").addText(encode(creationTime))
        }
        if let lastModificationTime = times.lastModificationTime {
            node.addElement("LastModificationTime").addText(encode(lastModificationTime))
        }
        if let lastAccessTime = times.lastAccessTime {
            node.addElement("LastAccessTime").addText(encode(lastAccessTime))
        }
        if let expiryTime = times.expiryTime {
            node.addElement("ExpiryTime").addText(encode(expiryTime))
        }
        if let expires = times.expires {
            node.addElement("Expires").addText(encode(expires))
        }
        if let usageCount = times.usageCount {
            node.addElement("UsageCount").addText(encode(usageCount))
        }
        if let locationChanged = times.locationChanged {
            node.addElement("LocationChanged").addText(encode(locationChanged))
        }
    }

    private func write(_ memoryProtection: KDBX.MemoryProtectionConfig, to node: Node) {
        if let protectTitle = memoryProtection.protectTitle {
            node.addElement("ProtectTitle").addText(encode(protectTitle))
        }
        if let protectUserName = memoryProtection.protectUserName {
            node.addElement("ProtectUserName").addText(encode(protectUserName))
        }
        if let protectPassword = memoryProtection.protectPassword {
            node.addElement("ProtectPassword").addText(encode(protectPassword))
        }
        if let protectURL = memoryProtection.protectURL {
            node.addElement("ProtectURL").addText(encode(protectURL))
        }
        if let protectNotes = memoryProtection.protectNotes {
            node.addElement("ProtectNotes").addText(encode(protectNotes))
        }
    }

    private func write(_ customIcon: KDBX.CustomIcon, to node: Node) {
        node.addElement("UUID").addText(encode(customIcon.uuid))
        node.addElement("Data").addText(encode(customIcon.data))
        if let name = customIcon.name {
            node.addElement("Name").addText(name)
        }
        if let lastModificationTime = customIcon.lastModificationTime {
            node.addElement("LastModificationTime").addText(encode(lastModificationTime))
        }
    }

    private func write(_ customData: KDBX.CustomDataWithTimes, to node: Node) {
        node.addElement("Key").addText(customData.key)
        node.addElement("Value").addText(customData.value)
        if let lastModificationTime = customData.lastModificationTime {
            node.addElement("LastModificationTime").addText(encode(lastModificationTime))
        }
    }

    private func write(_ customData: KDBX.CustomDataItem, to node: Node) {
        node.addElement("Key").addText(customData.key)
        node.addElement("Value").addText(customData.value)
    }

    private func write(_ deletedObject: KDBX.DeletedObject, to node: Node) {
        node.addElement("UUID").addText(encode(deletedObject.uuid))
        node.addElement("DeletionTime").addText(encode(deletedObject.deletionTime))
    }

    private func write(_ autoType: KDBX.AutoType, to node: Node) {
        if let enabled = autoType.enabled {
            node.addElement("Enabled").addText(encode(enabled))
        }

        if let dataTransferObfuscation = autoType.dataTransferObfuscation {
            let dtoNode = node.addElement("DataTransferObfuscation")
            switch dataTransferObfuscation {
            case .noObfuscation:
                dtoNode.addText("0")
            case .twoChannelObfuscation:
                dtoNode.addText("1")
            }
        }

        if let defaultSequence = autoType.defaultSequence {
            node.addElement("DefaultSequence").addText(defaultSequence)
        }

        for association in autoType.association {
            let associationNode = node.addElement("Association")
            associationNode.addElement("Window").addText(association.window)
            associationNode.addElement("KeystrokeSequence").addText(association.keystrokeSequence)
        }
    }

    func write(_ database: KDBX) throws(Error) {
        let document = Document()
        // `version="1.0"` is mandatory per XML 1.0 §2.8; without it some
        // strict XML parsers (notably KeePassXC's) reject the document and
        // report "No root group" or similar. Our reader is lenient enough
        // to accept the malformed form, which is what hid this for so long.
        document.declaration = XMLDeclaration(
            version: "1.0",
            encoding: "UTF-8",
            standalone: "yes"
        )
        let rootDocumentNode = document.makeDocumentElement(name: "KeePassFile")

        let metaNode = rootDocumentNode.addElement("Meta")
        write(database.meta, to: metaNode)
        let rootNode = rootDocumentNode.addElement("Root")
        write(database.root, to: rootNode)

        try write(document.xmlData(indentation: "\t"))
    }
}
