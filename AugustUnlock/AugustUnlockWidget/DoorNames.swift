import Foundation

/// The two button labels. Always two: a widget with no button under a tap
/// opens the app instead, which is the bug of 2026-11-01. A door whose lock
/// is not known yet is named by its position.
enum DoorNames {
    static let count = 2

    static func names(cached: [String]) -> [String] {
        (0..<count).map { $0 < cached.count ? cached[$0] : "Door \($0 + 1)" }
    }

    /// The lock ID per position, empty where no lock is known yet.
    static func ids(cached: [String]) -> [String] {
        (0..<count).map { $0 < cached.count ? cached[$0] : "" }
    }
}
