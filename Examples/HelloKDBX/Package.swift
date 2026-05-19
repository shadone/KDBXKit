// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "HelloKDBX",
    platforms: [
        .macOS(.v15),
    ],
    dependencies: [
        // Local-path dependency so the example tracks whatever is on
        // your KDBXKit working copy. A real downstream project would
        // depend on a tagged release via `.package(url:from:)`.
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "HelloKDBX",
            dependencies: [
                .product(name: "KDBXKit", package: "KDBXKit"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
    ]
)
