import AppIntents
import WidgetKit
import os

/// A widget tap: send unlock for that door and log the reply. Stateless by
/// design (Amit, 2026-11-01): the widget shows no state and never locks.
/// Unlock is idempotent, so a repeat is a no-op at the door. Cloud only, so a
/// tap takes the cloud's 1–25 s. The lock itself serialises this with
/// anything the app sends.
enum WidgetDoorAction {
    /// Under the 20–25 s that widget work is reported to get before iOS
    /// stops it.
    static let deadline: TimeInterval = 20

    static func unlock(position: Int) async {
        let locks = WidgetStore.locks
        WidgetLog.note("tap position=\(position) locks=\(locks.count)")
        guard locks.indices.contains(position) else {
            log.error("Widget tap at position \(position) has no lock; \(locks.count) cached")
            WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
            return
        }
        let door = locks[position]
        log.notice("Widget unlock of \(door.name, privacy: .public)")
        do {
            try await withDeadline(seconds: deadline) { try await WidgetCloud.unlock(lockID: door.id) }
            WidgetStore.signedOut = false
            WidgetLog.note("unlock position=\(position) ok")
        } catch {
            if case WidgetCloud.Failure.signedOut = error { WidgetStore.signedOut = true }
            log.error("Widget unlock of \(door.name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            WidgetLog.note("unlock position=\(position) failed: \(error.localizedDescription)")
        }
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}

struct DoorTimeout: LocalizedError {
    var errorDescription: String? { "Timed out" }
}

/// Runs `operation` with a deadline, so a hung command never holds the
/// widget's time budget. The slow side is cancelled; `URLSession` honours
/// that, though a request August already holds still runs.
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
