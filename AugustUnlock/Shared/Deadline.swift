import Foundation

struct DoorTimeout: LocalizedError {
    var errorDescription: String? { "Timed out" }
}

/// Runs `operation` with a deadline, so a hung command never holds the
/// process's time budget. The slow side is cancelled; `URLSession` and the
/// Bluetooth operation honour that, though a request August already holds
/// still runs.
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
