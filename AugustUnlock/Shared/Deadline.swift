import Foundation

nonisolated struct DoorTimeout: LocalizedError {
    var errorDescription: String? { "Timed out" }
}

/// Seconds left until `deadline`, never below zero.
nonisolated func secondsLeft(until deadline: ContinuousClock.Instant) -> TimeInterval {
    let left = ContinuousClock.now.duration(to: deadline)
    return max(0, Double(left.components.seconds) + Double(left.components.attoseconds) / 1e18)
}

/// Runs `operation` with a deadline, so a hung command never holds the
/// process's time budget. The slow side is cancelled; `URLSession` and the
/// Bluetooth operation honour that, though a request August already holds
/// still runs.
nonisolated func withDeadline<T: Sendable>(
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
