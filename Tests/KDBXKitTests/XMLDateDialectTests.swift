//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation
import Testing
@testable import KDBXKit

/// Focused coverage for `XMLDocumentReader.DateFormat`. KDBX 3.x stores
/// dates as ISO-8601 strings; KDBX 4.x packs them as base64 LE Int64
/// seconds since `0001-01-01`. The reader picks the dialect once at
/// init and dispatches `parseDate` accordingly — producers don't mix
/// the two within one file, so a single bad guess at construction time
/// would silently corrupt every date in the document.
///
/// The 3.1 fixture in `StaticReaderAPITests` exercises one canonical
/// ISO-8601 form (`...Z` with second precision). These tests pin the
/// other variants and the cross-dialect rejection.
@Suite("XMLDocumentReader date dialect")
struct XMLDateDialectTests {
    // MARK: - Test scaffolding

    /// Build a complete-enough KeePassFile XML carrying a single
    /// `<Meta><SettingsChanged>` date, parse it under the given
    /// dialect, and return the parsed value. `SettingsChanged` is
    /// optional in the model, so a failed parse surfaces as `nil`
    /// rather than as a typed error — except when the dialect
    /// dispatch throws .corrupted, which we test separately below.
    private func parseSettingsChanged(
        _ literal: String,
        dateFormat: XMLDocumentReader.DateFormat
    ) throws -> Date? {
        let xml = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <KeePassFile>
                <Meta>
                    <SettingsChanged>\(literal)</SettingsChanged>
                </Meta>
                <Root>
                    <Group>
                        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
                    </Group>
                </Root>
            </KeePassFile>
            """
        let reader = try XMLDocumentReader(
            xmlDocument: xml,
            keystreamSource: Self.mockKeystream(),
            dateFormat: dateFormat
        )
        return try reader.parse().meta.settingsChanged
    }

    private static func mockKeystream() -> KeystreamSource {
        KeystreamSource(
            algorithm: .chacha20,
            key: SecureBytes(Data(repeating: 0, count: 32)),
            nonce: Data(repeating: 0, count: 12)
        )
    }

    /// `2020-01-15T10:00:00Z` as a `Date` — derived from the ISO-8601
    /// parser rather than a hand-rolled magic number so the reference
    /// is the same value the production parser produces. Hardcoding a
    /// seconds-since-.NET-epoch literal here would just relitigate
    /// the conversion that ``Date(secondsSinceDotNetEpoch:)`` already
    /// implements (and stale-by-an-arithmetic-mistake would silently
    /// pass a wrong-but-self-consistent assertion).
    private static let reference: Date = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: "2020-01-15T10:00:00Z")!
    }()

    /// The same instant in the 4.x on-disk form (base64 little-endian
    /// Int64 seconds since 0001-01-01).
    private static let referenceAsDotNetTicksBase64: String =
        Self.reference.secondsSinceDotNetEpoch.toDataLittleEndian().base64EncodedString()

    // MARK: - ISO-8601 dialect

    @Test("Canonical Z-suffixed form (KeePassXC default) parses to the expected instant")
    func iso8601_canonicalZ() throws {
        let parsed = try parseSettingsChanged("2020-01-15T10:00:00Z", dateFormat: .iso8601)
        #expect(parsed == Self.reference)
    }

    @Test("Fractional-second ISO-8601 parses (some less-canonical 3.x writers add .000)")
    func iso8601_fractionalSeconds() throws {
        // .500 is half a second past — at second precision the
        // reader's Date(secondsSinceDotNetEpoch:) reference truncates
        // sub-second, so we just check non-nil + close-enough.
        let parsed = try parseSettingsChanged("2020-01-15T10:00:00.500Z", dateFormat: .iso8601)
        let expectedSeconds: TimeInterval = 0.5
        let actualOffset = try #require(parsed).timeIntervalSince(Self.reference)
        #expect(abs(actualOffset - expectedSeconds) < 0.001)
    }

    @Test("Numeric offset (+HH:MM) ISO-8601 parses to the same instant as Z form")
    func iso8601_numericOffset() throws {
        // 12:00:00+02:00 is 10:00:00Z.
        let parsed = try parseSettingsChanged("2020-01-15T12:00:00+02:00", dateFormat: .iso8601)
        #expect(parsed == Self.reference)
    }

    @Test("Malformed ISO-8601 throws .corrupted")
    func iso8601_malformed() throws {
        #expect(throws: XMLDocumentReader.Error.self) {
            try parseSettingsChanged("not-a-date", dateFormat: .iso8601)
        }
    }

    @Test("Base64 .NET ticks fed to the ISO-8601 dialect throws (no silent fallback)")
    func iso8601_rejectsBase64TicksInput() throws {
        // A producer mixing dialects within a file is malformed —
        // failing loudly is strictly better than silently misparsing.
        // ISO-8601 parser sees a base64 blob, can't decode it, throws.
        #expect(throws: XMLDocumentReader.Error.self) {
            try parseSettingsChanged(
                Self.referenceAsDotNetTicksBase64,
                dateFormat: .iso8601
            )
        }
    }

    // MARK: - .NET ticks dialect (4.x default; pin against regressions)

    @Test("Base64 .NET ticks parse under the default 4.x dialect")
    func dotNetTicks_canonical() throws {
        let parsed = try parseSettingsChanged(
            Self.referenceAsDotNetTicksBase64,
            dateFormat: .dotNetTicksBase64
        )
        #expect(parsed == Self.reference)
    }

    @Test("ISO-8601 fed to the .NET-ticks dialect throws (no silent fallback)")
    func dotNetTicks_rejectsISO8601Input() throws {
        // Same cross-dialect protection: 4.x reader sees an ISO-8601
        // string, tries to base64-decode it, fails, throws .corrupted.
        // Guards against future "be lenient and try both" changes
        // that would hide real producer bugs.
        #expect(throws: XMLDocumentReader.Error.self) {
            try parseSettingsChanged("2020-01-15T10:00:00Z", dateFormat: .dotNetTicksBase64)
        }
    }
}
