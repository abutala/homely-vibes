import Foundation
import os

/// Runs widget taps in the app process (see `ToggleDoorIntent`), one command
/// per door at a time. A new tap cancels that door's command in flight; over
/// Bluetooth a cancel before the write means the first command never reaches
/// the lock, and a cloud request August already holds can't be recalled —
/// the same limits as the app's button. Which command a tap sends is
/// `WidgetTapPolicy`'s call.
final class DoorToggler {
    static let shared = DoorToggler()

    private var policies: [String: WidgetTapPolicy] = [:]
    private var inFlight: [String: Task<OperationReply, Error>] = [:]
    /// Taps still running, counted from the start: the lock lookup can wait
    /// on the network before any command exists.
    private var runningTaps = 0

    private init() {}

    /// Read by the app's background exit check, so it never quits mid-command.
    var isBusy: Bool { runningTaps > 0 }

    func tap(slot: Int) async throws {
        runningTaps += 1
        defer { runningTaps -= 1 }
        let door = try await AugustClient.shared.lock(atSlot: slot)
        var policy = policies[door.id] ?? WidgetTapPolicy()
        let unlocking = policy.nextTapUnlocks(at: Date())
        policy.didSend(unlocking: unlocking)
        policies[door.id] = policy

        inFlight[door.id]?.cancel()
        let task = Task {
            try await unlocking ? AugustClient.shared.unlock(lockID: door.id) : AugustClient.shared.lock(lockID: door.id)
        }
        inFlight[door.id] = task
        Self.log.notice("Widget \(unlocking ? "unlock" : "lock", privacy: .public) for slot \(slot)")

        let reply: OperationReply?
        do {
            reply = try await task.value
        } catch {
            reply = nil
            Self.log.error("Widget command failed: \(error.localizedDescription, privacy: .public)")
        }
        // A newer tap replaced this one: its outcome is the one to record.
        guard inFlight[door.id] == task else { return }
        inFlight[door.id] = nil
        policies[door.id]?.didFinish(reportedUnlocked: reply?.state == .unlocked, at: Date())
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}
