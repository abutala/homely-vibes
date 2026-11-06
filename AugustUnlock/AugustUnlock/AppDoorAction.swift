import Foundation
import UIKit
import WidgetKit
import os

/// A widget tap, run in the app's process in the background: unlock that
/// door through the app's client (Bluetooth when the lock has a loaded key,
/// the cloud otherwise or on failure), and tell the widget what is
/// happening through `DoorStateStore`. Stateless by design (Amit,
/// 2026-11-01): nothing locks, and unlock is idempotent. The app's screen is
/// not involved: a background launch creates no scene (Logbook 2026-11-02).
enum AppDoorAction {
    /// The widget's Bluetooth budgets: a background process gets slower
    /// Bluetooth from iOS, so setup gets 6 s; the whole tap is bounded by
    /// `DoorState.tapLimit` (iOS ends a background intent at about 30 s),
    /// so a miss costs the cloud leg at most 6 s. (The screen waits longer:
    /// `CommandDeadline`.)
    static let bluetoothSetupBudget: TimeInterval = 6
    static let bluetoothOperationBudget: TimeInterval = 12

    /// Widget taps running in this process: the screen's 5-minute exit
    /// waits for them (`ContentView`), as it does for its own command.
    static var inFlight: Int { running.withLock { $0 } }
    private static let running = OSAllocatedUnfairLock(initialState: 0)

    /// `lockID` is the lock the widget showed under this button; empty when
    /// the widget had no lock list yet (the real client refuses it). `client`
    /// is the app's August client, or the fake on the Simulator
    /// (`August.shared` picks).
    static func unlock(position: Int, lockID: String, client: any DoorUnlocking = August.shared) async {
        let deadline = ContinuousClock.now + .seconds(DoorState.tapLimit)
        // A repeat tap on a door whose unlock is still running would only
        // queue a duplicate command; the first tap answers both. The check
        // and the start are one locked step.
        guard DoorStateStore.update({ $0.start(position, at: Date()) }) else {
            AppLog.note("widget tap position=\(position) ignored: still running")
            return
        }
        running.withLock { $0 += 1 }
        defer { running.withLock { $0 -= 1 } }
        AppLog.note("widget tap position=\(position) lock=\(lockID.suffix(4)) via \(type(of: client)) door state keychain=\(KeychainStore.lastStatus)")
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        let start = ContinuousClock.now
        var outcome = DoorState.Outcome.failed
        if TestHooks.slowWidgetTap { try? await Task.sleep(for: .seconds(5)) }
        do {
            let reply = try await client.unlock(
                lockID: lockID, bluetoothSetupBudget: bluetoothSetupBudget, bluetoothOperationBudget: bluetoothOperationBudget,
                deadline: deadline, keepLink: false)
            outcome = .ok
            AppLog.note("widget unlock position=\(position) ok via \(reply.path.rawValue) in \(start.duration(to: .now))")
        } catch {
            if case AugustError.cloudNoReply = error { outcome = .noReply }
            AppLog.note("widget unlock position=\(position) \(outcome) in \(start.duration(to: .now)): \(error.localizedDescription)")
            log.error("Widget unlock at position \(position) failed: \(error.localizedDescription, privacy: .public)")
        }
        DoorStateStore.update { $0.finish(position, outcome: outcome, at: Date()) }
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}

/// `Library/Caches/app.log` in the app's container, last 200 lines: every
/// timing line `os_log` keeps only in a buffer the phone soon overwrites.
let AppLog = LineLog(file: "app.log", keep: 200, category: "timing")
