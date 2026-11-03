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
    /// Under the budget iOS gives a background intent.
    static let deadline: TimeInterval = 20

    static func unlock(position: Int) async {
        DoorStateStore.update { $0.start(position) }
        AppLog.note("widget tap position=\(position) door state keychain=\(DoorStateStore.lastStatus)")
        WidgetCenter.shared.reloadTimelines(ofKind: "Doors")
        let start = ContinuousClock.now
        var ok = false
        do {
            let locks = try await AugustClient.shared.knownLocks()
            guard locks.indices.contains(position) else { throw AugustError.noLocks }
            let reply = try await withDeadline(seconds: deadline) {
                try await AugustClient.shared.unlock(lockID: locks[position].id)
            }
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
