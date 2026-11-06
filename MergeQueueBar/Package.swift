// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MergeQueueBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "MergeQueueBar",
            path: "Sources/MergeQueueBar",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "MergeQueueBarTests",
            dependencies: ["MergeQueueBar"],
            path: "Tests/MergeQueueBarTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
