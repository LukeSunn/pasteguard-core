// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PasteGuardCore",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "PasteGuardCore",
            targets: ["PasteGuardCore"]
        ),
    ],
    targets: [
        .target(
            name: "PasteGuardCore",
            path: "Sources/PasteGuardCore"
        ),
        .testTarget(
            name: "PasteGuardCoreTests",
            dependencies: ["PasteGuardCore"],
            path: "Tests/PasteGuardCoreTests"
        ),
    ]
)
