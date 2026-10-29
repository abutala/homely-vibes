// swift-tools-version: 6.0
// Builds only the pure files (Bluetooth protocol, exit policy, door record), so
// `swift test` can check them on the Mac. The app builds from AugustUnlock.xcodeproj.
import PackageDescription

let package = Package(
    name: "AugustUnlock",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "AugustBLEProtocol",
            path: ".",
            sources: [
                "AugustUnlock/AugustBLEProtocol.swift", "AugustUnlock/BackgroundExitPolicy.swift",
                "Shared/DoorState.swift",
            ],
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
