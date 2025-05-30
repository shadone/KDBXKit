//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//

import Foundation

extension Date {
    /// The .NET DateTime epoch: `0001-01-01 00:00:00 UTC`.
    ///
    /// Used as the reference point for date encoding in KDBX files, which follow the
    /// .NET serialization format for date values.
    private static let dotNetEpoch = DateComponents(
        calendar: Calendar(identifier: .gregorian),
        timeZone: TimeZone(secondsFromGMT: 0),
        year: 1,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0
    ).date!

    /// The number of seconds between this date and the .NET epoch (`0001-01-01T00:00:00Z`),
    /// rounded to the nearest second.
    ///
    /// This value matches how dates are encoded in KDBX files.
    var secondsSinceDotNetEpoch: Int64 {
        Int64(timeIntervalSince(Self.dotNetEpoch).rounded())
    }

    /// Creates a `Date` from the number of seconds since the .NET epoch (`0001-01-01T00:00:00Z`).
    ///
    /// This is used to decode timestamp values found in KeePass KDBX documents.
    ///
    /// - Parameter seconds: The number of seconds since the .NET epoch.
    init(secondsSinceDotNetEpoch seconds: Int64) {
        self = Self.dotNetEpoch.addingTimeInterval(TimeInterval(seconds))
    }
}
