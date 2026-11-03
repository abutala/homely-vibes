import Foundation
import WidgetKit
import os

/// A widget tap, run in the app's process in the background: unlock that
/// door through the app's client (Bluetooth when the lock has a loaded key,
/// the cloud otherwise or on failure), and tell the widget what is
/// happening through `DoorStateStore`. Stateless by design (Amit,
/// 2026-11-01): nothing locks, and unlock is idempotent. The app's screen is
/// not involved: a background launch creates no scene (Logbook 2026-11-02).
enum AppDoorAction {
    /// The cloud leg's own deadline, from the moment it starts: the garage's
    /// cloud path took 21 s on the phone (app.log, 2026-11-03), so 20 was
    /// too short. The Bluetooth attempt before it is bounded on its own.
    static let cloudDeadline: TimeInterval = 25
    /// Bluetooth setup from a background process is slower than from the
    /// screen: the key exchange stalled at 3 s and at 6 s until the app
    /// declared the `bluetooth-central` background mode, without which a
    /// backgrounded app gets no Bluetooth events. The cloud fallback keeps
    /// its own deadline, so this costs the tap at most 6 s on a miss.
    static let bluetoothSetupBudget: TimeInterval = 6

    /// `lockID` is the lock the widget showed under this button; empty when
    /// the widget had no lock list yet.
    static func unlock(position: Int, lockID: String) async {
        // A repeat tap on a door whose unlock is still running would only
        // queue a duplicate command; the first tap answers both. The check
        // and the start are one locked step.
        guard DoorStateStore.update({ $0.start(position, at: Date()) }) else {
            AppLog.note("widget tap position=\(position) ignored: still running")
            return
        }
        AppLog.note("widget tap position=\(position) lock=\(lockID.suffix(4)) door state keychain=\(DoorStateStore.lastStatus)")
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        let start = ContinuousClock.now
        var ok = false
        if TestHooks.slowWidgetTap { try? await Task.sleep(for: .seconds(5)) }
        do {
            guard !lockID.isEmpty else { throw AugustError.noLocks }
            let reply = try await AugustClient.shared.unlock(
                lockID: lockID, bluetoothSetupBudget: bluetoothSetupBudget, cloudDeadline: cloudDeadline)
            ok = true
            AppLog.note("widget unlock position=\(position) ok via \(reply.path.rawValue) in \(start.duration(to: .now))")
        } catch {
            AppLog.note("widget unlock position=\(position) failed in \(start.duration(to: .now)): \(error.localizedDescription)")
            log.error("Widget unlock at position \(position) failed: \(error.localizedDescription, privacy: .public)")
        }
        DoorStateStore.update { $0.finish(position, ok: ok, at: Date()) }
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
    }

    private static let log = Logger(subsystem: "AugustUnlock", category: "widget")
}

/// The app's own log file, beside the widget's: `Library/Caches/app.log`,
/// readable off the phone with `xcrun devicectl device copy from
/// --domain-type appDataContainer --domain-identifier <app bundle id>
/// --source Library/Caches/app.log`. The timing lines `os_log` keeps only in
/// a buffer the phone soon overwrites live here too. Last 200 lines kept.
enum AppLog {
    private static var url: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("app.log")
    }

    /// Lines come from several tasks at once (key refreshes, a tap, the
    /// screen); each read-append-write is one step.
    private static let lock = OSAllocatedUnfairLock()

    static func note(_ message: String) {
        lock.withLock {
            let stamp = ISO8601DateFormatter().string(from: Date())
            var lines = (try? String(contentsOf: url, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? []
            lines.append("\(stamp) \(message)")
            try? lines.suffix(200).joined(separator: "\n").appending("\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
