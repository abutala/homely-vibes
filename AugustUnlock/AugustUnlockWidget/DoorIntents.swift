import AppIntents
import WidgetKit
import os

/// One intent type per door position, with no parameters, run by the widget
/// itself in the background. `.plain` button styles are inert in this install
/// and a parameter was ruled out separately, so the types stay as plain as
/// this. The label and the command read the same `WidgetStore.locks` entry,
/// so a door's name always matches the lock it acts on.
struct ToggleFirstDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle First Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    func perform() async throws -> some IntentResult {
        await WidgetDoorAction.tap(position: 0)
        return .result()
    }
}

struct ToggleSecondDoorIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle Second Door"
    static let isDiscoverable = false
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    func perform() async throws -> some IntentResult {
        await WidgetDoorAction.tap(position: 1)
        return .result()
    }
}

/// A widget tap: decide from the widget's own record, mark it running, send
/// the cloud command, record the reply. Cloud only, so a tap takes the
/// cloud's 5–9 s. It shares nothing with a command the app runs; the lock
/// itself serialises them.
enum WidgetDoorAction {
    /// Under the 20–25 s that widget work is reported to get before iOS
    /// stops it; a stopped command would leave "running" stuck until
    /// `DoorRecord.runningTimeout`.
    static let deadline: TimeInterval = 20

    static func tap(position: Int) async {
        let locks = WidgetStore.locks
        guard locks.indices.contains(position) else {
            log.error("Widget tap at position \(position) has no lock; \(locks.count) cached")
            return
        }
        let door = locks[position]
        let before = WidgetStore.record(for: door.id)
        let unlocking = before.nextTapUnlocks(at: Date())
        WidgetStore.write(DoorRecord(state: before.state, running: unlocking, at: Date()), for: door.id)
        WidgetCenter.shared.reloadAllTimelines()
        log.notice("Widget \(unlocking ? "unlock" : "lock", privacy: .public) of \(door.name, privacy: .public)")

        var state = DoorRecord.State.unknown
        do {
            state = try await withDeadline(seconds: deadline) {
                try await WidgetCloud.operate(lockID: door.id, unlocking: unlocking)
            }
        } catch {
            log.error("Widget command for \(door.name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
        WidgetStore.write(DoorRecord(state: state, running: nil, at: Date()), for: door.id)
        WidgetCenter.shared.reloadAllTimelines()
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}

struct DoorTimeout: LocalizedError {
    var errorDescription: String? { "Timed out" }
}

/// Runs `operation` with a deadline, so a hung command never leaves a
/// circle running. The slow side is cancelled; `URLSession` honours that.
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
