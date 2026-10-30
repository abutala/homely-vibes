import SwiftUI

/// What one door's circle in the widget shows.
enum DoorDisplay: Equatable {
    case unknown
    case locked
    case unlocked
    case locking
    case unlocking

    init(_ record: DoorRecord) {
        if let running = record.running {
            self = running ? .unlocking : .locking
            return
        }
        switch record.state {
        case .locked: self = .locked
        case .unlocked: self = .unlocked
        case .unknown: self = .unknown
        }
    }

    var color: Color {
        switch self {
        case .unlocked, .unlocking: return .green
        case .locked, .locking: return .red
        case .unknown: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .unlocked: return "lock.open.fill"
        case .locked: return "lock.fill"
        case .unlocking, .locking: return "ellipsis"
        case .unknown: return "questionmark"
        }
    }

    var caption: String {
        switch self {
        case .unknown: return "Tap to unlock"
        case .locked: return "Locked"
        case .unlocked: return "Unlocked"
        case .locking: return "Locking…"
        case .unlocking: return "Unlocking…"
        }
    }
}
