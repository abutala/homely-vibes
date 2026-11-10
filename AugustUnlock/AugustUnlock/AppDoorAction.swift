import Foundation
import UIKit
import WidgetKit
import os

/// A widget tap, run in the app's process in the background: unlock that
/// door, or lock both, through the app's client, over Bluetooth and the cloud
/// at the same moment (`DoorPaths.both`; Amit, 2026-11-09), and tell the widget
/// what is happening through `DoorStateStore`. Stateless by design (Amit, 2026-11-01):
/// lock and unlock are idempotent. The app's screen is not involved: a
/// background launch creates no scene (Logbook 2026-11-02).
enum AppDoorAction {
    /// The widget's Bluetooth budgets. The cloud command goes out with
    /// Bluetooth, so a slow connect costs the cloud nothing and may take
    /// the whole tap (`DoorState.tapLimit`; iOS ends a background intent at
    /// about 30 s). The 6 s it had before sent four taps in eleven to a cloud
    /// leg that started late (Logbook 2026-11-09).
    static let bluetoothSetupBudget = DoorState.tapLimit
    static let bluetoothOperationBudget: TimeInterval = 12

    /// Widget taps running in this process: the screen's 5-minute exit
    /// waits for them, as it does for its own commands.
    static var inFlight: Int { running.withLock { $0 } }
    private static let running = OSAllocatedUnfairLock(initialState: 0)

    /// `lockID` is the lock the widget showed under this button; empty when
    /// the widget had no lock list yet (the real client refuses it); `name`
    /// is its name there, for the Live Activity. `client` is the app's
    /// August client, or the fake on the Simulator (`August.shared` picks).
    static func unlock(position: Int, lockID: String, name: String, client: any DoorCommands = August.shared) async {
        await runTap(position: position, door: name.isEmpty ? "Door" : name, first: .unlocking, final: DoorStage.final) { deadline in
            let start = ContinuousClock.now
            do {
                let reply = try await client.unlock(
                    lockID: lockID, paths: .both, bluetoothSetupBudget: bluetoothSetupBudget, bluetoothOperationBudget: bluetoothOperationBudget,
                    deadline: deadline, keepLink: false, onStage: { _ in })
                if let tail = reply.tail { watch(tail, position: position) }
                AppLog.note("widget unlock position=\(position) ok via \(reply.path.rawValue) in \(start.duration(to: .now))\(reply.tail == nil ? "" : "; August's copy still out")")
                return .ok
            } catch {
                return outcome(of: error, "widget unlock position=\(position)", since: start)
            }
        }
    }

    /// Bluetooth unlocked the door and August still holds the same unlock,
    /// which can land after a later lock. The mark is written now, before
    /// the tap returns, and only August's reply removes it: a process that
    /// iOS suspends or ends in between leaves it (TRIAL 2026-11-09). A lock's
    /// tail needs none: it moves the door the way a later lock would. The
    /// removal has its own background time: without it iOS may suspend the
    /// process between August's reply and the write, and Lock Both would
    /// read "No reply" for a minute over a confirmed unlock.
    private static func watch(_ tail: CloudTail, position: Int) {
        DoorStateStore.update { $0.tailOpened(position, at: tail.openedAt) }
        let keepAlive = BackgroundTask(name: "AugustTailMark")
        Task {
            if await tail.confirmed() { DoorStateStore.update { $0.tailConfirmed(position, openedAt: tail.openedAt) } }
            keepAlive.end()
        }
    }

    /// Both doors at once, each under the one tap's deadline: the per-lock
    /// gates keep a door's commands in order, so a lock tapped over a running
    /// unlock runs after it. The center reads "Locked" only if both confirm.
    static func lockBoth(lockIDs: [String], client: any DoorCommands = August.shared) async {
        let tapped = Date()
        await runTap(position: DoorState.lockBothPosition, door: "Both Doors", first: .locking, final: DoorStage.finalForLock) { deadline in
            let outcomes = await withTaskGroup(of: (Int, DoorState.Outcome).self) { group in
                for (position, lockID) in lockIDs.enumerated() {
                    group.addTask {
                        (position, await lock(position: position, lockID: lockID, deadline: deadline, client: client))
                    }
                }
                var outcomes = [DoorState.Outcome](repeating: .failed, count: lockIDs.count)
                for await (position, outcome) in group { outcomes[position] = outcome }
                return outcomes
            }
            return DoorStateStore.update { $0.recordLocks(outcomes, startedAt: tapped, at: Date()) }
        }
    }

    private static func lock(
        position: Int, lockID: String, deadline: ContinuousClock.Instant, client: any DoorCommands
    ) async -> DoorState.Outcome {
        let start = ContinuousClock.now
        do {
            let reply = try await client.lock(
                lockID: lockID, paths: .both, bluetoothSetupBudget: bluetoothSetupBudget, bluetoothOperationBudget: bluetoothOperationBudget,
                deadline: deadline, keepLink: false, onStage: { _ in })
            AppLog.note("widget lock position=\(position) \(reply.state.label) via \(reply.path.rawValue) in \(start.duration(to: .now))")
            return reply.state.lockOutcome
        } catch {
            return outcome(of: error, "widget lock position=\(position)", since: start)
        }
    }

    private static func outcome(of error: Error, _ what: String, since start: ContinuousClock.Instant) -> DoorState.Outcome {
        var outcome = DoorState.Outcome.failed
        if case AugustError.cloudNoReply = error { outcome = .noReply }
        AppLog.note("\(what) \(outcome) in \(start.duration(to: .now)): \(error.localizedDescription)")
        log.error("\(what, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        return outcome
    }

    /// One tap's frame: its mark, its Live Activity, its deadline and its
    /// result. A repeat tap on a position still running would only queue a
    /// duplicate command; the first tap answers both. The check and the start
    /// are one locked step.
    private static func runTap(
        position: Int, door: String, first: DoorStage, final: (DoorState.Outcome) -> DoorStage,
        command: (ContinuousClock.Instant) async -> DoorState.Outcome
    ) async {
        let deadline = ContinuousClock.now + .seconds(DoorState.tapLimit)
        let started = Date()
        guard DoorStateStore.update({ $0.start(position, at: started) }) else {
            AppLog.note("widget tap position=\(position) ignored: still running")
            return
        }
        // Only a tap with no other in flight gets a Live Activity: two at
        // once empty the Island early (Logbook 2026-11-07). The other button
        // still shows its progress on the widget.
        let alone = running.withLock { $0 += 1; return $0 == 1 }
        defer { running.withLock { $0 -= 1 } }
        AppLog.note("widget tap position=\(position) door state keychain=\(KeychainStore.lastStatus)")
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        let start = ContinuousClock.now
        let live = alone ? await DoorLiveActivity.start(door: door, first: first, at: Date()) : nil
        if !alone { AppLog.note("widget tap position=\(position) without a live activity: another tap runs") }
        if TestHooks.slowWidgetTap { try? await Task.sleep(for: .seconds(5)) }
        let outcome = await command(deadline)
        let elapsed = start.duration(to: .now).components
        // The widget's result first: it is the one surface a tap cut off at
        // the ~30 s limit must not lose.
        DoorStateStore.update { $0.finish(position, startedAt: started, outcome: outcome, at: Date()) }
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        await live?.end(final(outcome), seconds: Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18)
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}

/// `Library/Caches/app.log` in the app's container, last 600 lines: every
/// timing line `os_log` keeps only in a buffer the phone soon overwrites.
nonisolated let AppLog = LineLog(file: "app.log", keep: 600, category: "timing")
