// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftLDAP",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "SwiftLDAP",
            targets: ["SwiftLDAP"]
        ),
    ],
    targets: [
        .target(
            name: "SwiftLDAP"
        ),
        .testTarget(
            name: "SwiftLDAPTests",
            dependencies: ["SwiftLDAP"]
        ),
    ]
)
