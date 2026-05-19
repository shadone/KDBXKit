// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KDBX",
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
        .package(url: "https://github.com/P-H-C/phc-winner-argon2.git", branch: "master"),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    ],
    targets: [
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
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
        ),
        .target(
            name: "KDBXKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "argon2", package: "phc-winner-argon2"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ],
            linkerSettings: [
                .linkedLibrary("z"),
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
    ]
)
