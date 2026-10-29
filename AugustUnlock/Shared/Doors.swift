import Foundation

/// The doors as the app and the widget name them. `slot` is the lock's index
/// in the account's lock list sorted by lock ID (`AugustClient.cachedLocks`);
/// on this account the garage sorts first. Checked on the phone (2026-10-28).
enum Doors {
    struct Door {
        let name: String
        let slot: Int
    }

    static let all = [
        Door(name: "Front door", slot: 1),
        Door(name: "Garage", slot: 0),
    ]

    static func slot(named name: String) -> Int {
        all.first { $0.name == name }?.slot ?? 0
    }

    static func name(forSlot slot: Int) -> String? {
        all.first { $0.slot == slot }?.name
    }
}

struct DoorTimeout: LocalizedError {
    var errorDescription: String? { "Timed out — tap to retry" }
}

/// Runs `operation` with a deadline: a command that hangs must never leave a
/// circle pulsing or the app waiting. The slow side is cancelled.
func withDeadline<T: Sendable>(
    seconds: TimeInterval, _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw DoorTimeout()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}
