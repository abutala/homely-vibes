import AppIntents
import WidgetKit
import os

/// One intent type per door position, with no parameters, run by the widget
/// itself in the background. `.plain` button styles are inert in this install
/// and a parameter was ruled out separately, so the types stay as plain as
/// this. The label and the command read the same `WidgetStore.locks` entry
/// by position. Only a change to the account's lock list can move a lock to
/// another position, and the widget redraws with the new list at once.
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
/// cloud's 5–9 s. A tap while one runs doesn't cancel it: the newer tap owns
/// the record, so the older reply is dropped, not shown. It shares nothing
/// with a command the app runs; the lock itself serialises them.
enum WidgetDoorAction {
    /// Under the 20–25 s that widget work is reported to get before iOS
    /// stops it; a stopped command would leave "running" stuck until
    /// `DoorRecord.runningTimeout`. Kept below that timeout, so a reply can
    /// never land after its own run has expired.
    static let deadline: TimeInterval = min(20, DoorRecord.runningTimeout - 5)

    static func tap(position: Int) async {
        let locks = WidgetStore.locks
        guard locks.indices.contains(position) else {
            log.error("Widget tap at position \(position) has no lock; \(locks.count) cached")
            return
        }
        let door = locks[position]
        let before = WidgetStore.record(for: door.id)
        let unlocking = before.nextTapUnlocks(at: Date())
        WidgetStore.lastTap = Date()
        let sent = DoorRecord(state: before.state, running: unlocking, at: Date())
        WidgetStore.write(sent, for: door.id)
        WidgetCenter.shared.reloadAllTimelines()
        log.notice("Widget \(unlocking ? "unlock" : "lock", privacy: .public) of \(door.name, privacy: .public)")

        var state = DoorRecord.State.unknown
        do {
            state = try await withDeadline(seconds: deadline) {
                try await WidgetCloud.operate(lockID: door.id, unlocking: unlocking)
            }
            WidgetStore.signedOut = false
        } catch {
            if case WidgetCloud.Failure.signedOut = error { WidgetStore.signedOut = true }
            log.error("Widget command for \(door.name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
        // Compared within 1 ms, not with `==`: the record went through JSON.
        let now = WidgetStore.record(for: door.id)
        guard now.running == sent.running, abs(now.at.timeIntervalSince(sent.at)) < 0.001 else {
            log.notice("Widget reply for \(door.name, privacy: .public) dropped: a newer tap owns the door")
            return
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
