import Foundation
import UIKit
import WidgetKit
import os

/// A widget tap, run in the app's process in the background: unlock that
/// door, or lock both, through the app's client (Bluetooth when the lock has a
/// loaded key, the cloud otherwise or on failure), and tell the widget what is
/// happening through `DoorStateStore`. Stateless by design (Amit, 2026-11-01):
/// lock and unlock are idempotent. The app's screen is not involved: a
/// background launch creates no scene (Logbook 2026-11-02).
enum AppDoorAction {
    /// A widget tap has the screen's Bluetooth budgets (`CommandDeadline`):
    /// 12 s to reach a session, 6 s from there. With 6 s to set up, four
    /// widget connects in eleven missed and went to the cloud, which is slow
    /// (8–25 s) and made the front lock beep 12 times on a lock (Logbook
    /// 2026-11-09). The cloud is the fallback only (Amit, 2026-11-09). The
    /// whole tap is bounded by `DoorState.tapLimit` (iOS ends a background
    /// intent at about 30 s), so a setup miss leaves the cloud 16 s, a
    /// failure after the session 10 s (`CommandDeadlineTests` pins both).

    /// Widget taps running in this process: the screen's 5-minute exit
    /// waits for them, as it does for its own commands.
    static var inFlight: Int { running.withLock { $0 } }
    private static let running = OSAllocatedUnfairLock(initialState: 0)

    /// `lockID` is the lock the widget showed under this button; empty when
    /// the widget had no lock list yet (the real client refuses it); `name`
    /// is its name there, for the Live Activity. `client` is the app's
    /// August client, or the fake on the Simulator (`August.shared` picks).
    static func unlock(position: Int, lockID: String, name: String, client: any DoorCommands = August.shared) async {
        await runTap(position: position, door: name.isEmpty ? "Door" : name, first: .unlocking, final: DoorStage.final) { deadline, onStage in
            let start = ContinuousClock.now
            do {
                let reply = try await client.unlock(
                    lockID: lockID, bluetoothSetupBudget: CommandDeadline.bluetoothSetup, bluetoothOperationBudget: CommandDeadline.bluetoothOperation,
                    deadline: deadline, keepLink: false, onStage: onStage)
                AppLog.note("widget unlock position=\(position) ok via \(reply.path.rawValue) in \(start.duration(to: .now))")
                return .ok
            } catch {
                return outcome(of: error, "widget unlock position=\(position)", since: start)
            }
        }
    }

    /// Both doors at once, each under the one tap's deadline: the per-lock
    /// gates keep a door's commands in order, so a lock tapped over a running
    /// unlock runs after it. The center reads "Locked" only if both confirm.
    static func lockBoth(lockIDs: [String], client: any DoorCommands = August.shared) async {
        let tapped = Date()
        await runTap(position: DoorState.lockBothPosition, door: "Both Doors", first: .locking, final: DoorStage.finalForLock) { deadline, onStage in
            let outcomes = await withTaskGroup(of: (Int, DoorState.Outcome).self) { group in
                for (position, lockID) in lockIDs.enumerated() {
                    group.addTask {
                        (position, await lock(position: position, lockID: lockID, deadline: deadline, onStage: onStage, client: client))
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
        position: Int, lockID: String, deadline: ContinuousClock.Instant, onStage: @escaping @Sendable (DoorStage) -> Void, client: any DoorCommands
    ) async -> DoorState.Outcome {
        let start = ContinuousClock.now
        do {
            let reply = try await client.lock(
                lockID: lockID, bluetoothSetupBudget: CommandDeadline.bluetoothSetup, bluetoothOperationBudget: CommandDeadline.bluetoothOperation,
                deadline: deadline, keepLink: false, onStage: onStage)
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
        command: (ContinuousClock.Instant, @escaping @Sendable (DoorStage) -> Void) async -> DoorState.Outcome
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
        let outcome = await command(deadline) { live?.show($0) }
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
let AppLog = LineLog(file: "app.log", keep: 600, category: "timing")
