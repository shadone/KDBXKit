// swift-tools-version: 6.1
//
// Copyright (c) 2025, Denis Dzyubenko <denis@ddenis.info>
//
// SPDX-License-Identifier: BSD-2-Clause
//
// The swift-tools-version declares the minimum version of Swift required to build this package.

import Foundation
import PackageDescription

// Fuzz targets are declared only under KDBXKIT_FUZZ=1 so a normal build/test/Xcode
// build never sees them. They require the swift.org toolchain + -sanitize=fuzzer
// (the Xcode toolchain cannot build them); see Fuzz/README.md.
let fuzzSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .unsafeFlags(["-parse-as-library"]),
]

var fuzzTargets: [Target] = []
if ProcessInfo.processInfo.environment["KDBXKIT_FUZZ"] == "1" {
    fuzzTargets = [
        .executableTarget(name: "FuzzHeader", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzHeader", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzParse", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzParse", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzXML", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzXML", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzVariantDict", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzVariantDict", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzBlockStream", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzBlockStream", swiftSettings: fuzzSwiftSettings),
        .executableTarget(name: "FuzzSeedGen", dependencies: ["KDBXKit"], path: "Fuzz/Sources/FuzzSeedGen", swiftSettings: [.swiftLanguageMode(.v6)]),
    ]
}

let package = Package(
    name: "KDBXKit",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    products: [
        .executable(
            name: "kdbx",
            targets: ["kdbx-cli"],
        ),
        .library(
            name: "KDBXKit",
            targets: ["KDBXKit"],
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0"),
    ],
    targets: [
        .systemLibrary(
            name: "CZlib",
            path: "Sources/CZlib",
            pkgConfig: "zlib",
            providers: [
                .apt(["zlib1g-dev"]),
                .brew(["zlib"]),
            ],
        ),
        .executableTarget(
            name: "kdbx-cli",
            dependencies: [
                "KDBXCLICore",
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
        ),
        .target(
            name: "KDBXCLICore",
            dependencies: [
                "KDBXKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
        ),
        .testTarget(
            name: "KDBXCLICoreTests",
            dependencies: ["KDBXCLICore", "KDBXKit"],
            resources: [
                .copy("Resources"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
        ),
        .target(
            name: "argon2",
            path: "Sources/CArgon2",
            exclude: [
                "CHANGELOG.md",
                "LICENSE",
                "UPSTREAM.md",
            ],
            sources: [
                "src/argon2.c",
                "src/core.c",
                "src/encoding.c",
                "src/ref.c",
                "src/thread.c",
                "src/blake2/blake2b.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("src"),
                .headerSearchPath("src/blake2"),
            ],
        ),
        .target(
            name: "KDBXKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                "CZlib",
                "argon2",
            ],
            resources: [
                // Apple-platform privacy manifest. Declares no
                // tracking, no data collection, no required-reason
                // API usage. Apple-only — ignored on Linux builds.
                .copy("PrivacyInfo.xcprivacy"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
        ),
        .testTarget(
            name: "KDBXKitTests",
            dependencies: ["KDBXKit"],
            resources: [
                .copy("Resources"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
        ),
    ] + fuzzTargets
)
