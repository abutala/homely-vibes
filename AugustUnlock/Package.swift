// swift-tools-version: 6.0
// Builds only the pure Bluetooth protocol file, so `swift test` can check it
// on the Mac. The app itself builds from AugustUnlock.xcodeproj.
import PackageDescription

let package = Package(
    name: "AugustUnlock",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "AugustBLEProtocol",
            path: "AugustUnlock",
            exclude: [
                "Assets.xcassets", "AugustClient.swift", "AugustBLEOperation.swift",
                "AugustUnlockApp.swift", "ContentView.swift", "KeychainStore.swift",
            ],
            sources: ["AugustBLEProtocol.swift"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "AugustBLEProtocolTests",
            dependencies: ["AugustBLEProtocol"],
            path: "Tests/AugustBLEProtocolTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
