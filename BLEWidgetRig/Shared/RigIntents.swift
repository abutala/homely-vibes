import AppIntents
import WidgetKit
import os

#if !WIDGET_EXTENSION
    import UIKit

    /// A UIKit background task with an idempotent end; iOS calls the expiry
    /// handler when it takes the time back.
    final class RigBackgroundTask: Sendable {
        private let id: UIBackgroundTaskIdentifier
        private let ended = OSAllocatedUnfairLock(initialState: false)

        init(name: String, onExpire: @escaping @Sendable () -> Void) {
            var identifier = UIBackgroundTaskIdentifier.invalid
            let ended = ended
            identifier = UIApplication.shared.beginBackgroundTask(withName: name) {
                onExpire()
                if !ended.withLock({ let was = $0; $0 = true; return was }) { UIApplication.shared.endBackgroundTask(identifier) }
            }
            id = identifier
        }

        func end() {
            guard id != .invalid, !ended.withLock({ let was = $0; $0 = true; return was }) else { return }
            let id = id
            DispatchQueue.main.async { UIApplication.shared.endBackgroundTask(id) }
        }
    }
#endif

/// The widget's first button: the probe as AugustUnlock's widget runs its
/// unlock, in the app's process in the background (`supportedModes` with
/// `.foreground(.dynamic)`; the app never comes forward).
struct RigBackgroundProbeIntent: AppIntent {
    static let title: LocalizedStringResource = "Probe in the background"
    static let isDiscoverable = false
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    func perform() async throws -> some IntentResult {
        await RigTap.probe(label: "widget-background")
        return .result()
    }
}

/// The widget's second button: the trade-off Tesla's widget takes. The
/// system opens the app, then runs the probe in it, in the foreground.
struct RigForegroundProbeIntent: AppIntent {
    static let title: LocalizedStringResource = "Probe in the foreground"
    static let isDiscoverable = false
    static let openAppWhenRun = true

    func perform() async throws -> some IntentResult {
        await RigTap.probe(label: "widget-foreground")
        return .result()
    }
}

/// The widget's third button, the measurement behind AugustUnlock's
/// "progress on the widget" question: `perform()` returns at once and the
/// work runs detached under a background task. The log then says how long
/// the process lives after the return, whether the Bluetooth echo still
/// completes, and when each reload asked after the return is run and drawn.
struct RigDetachedProbeIntent: AppIntent {
    static let title: LocalizedStringResource = "Probe detached"
    static let isDiscoverable = false
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    func perform() async throws -> some IntentResult {
        await RigTap.detached()
        return .result()
    }
}

enum RigTap {
    /// Writes the tap's start for the widget, begins the background task,
    /// starts the detached work, returns. Everything it learns goes to
    /// `rig.log` under the label `detached`.
    static func detached() async {
        #if WIDGET_EXTENSION
            let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("rig-extension.log")
            try? "\(Date()) detached ran in the widget extension\n".write(to: url, atomically: true, encoding: .utf8)
        #else
            let started = Date()
            RigMark.set(started)
            let remaining = await MainActor.run { UIApplication.shared.backgroundTimeRemaining }
            RigNote.write("rig.log", "detached: perform start, app state \(RigProbe.appState), background time remaining \(Self.describe(remaining))")
            let task = RigBackgroundTask(name: "RigDetached") {
                RigNote.write("rig.log", "detached: background task EXPIRED at \(Self.seconds(since: started)) s")
            }
            Task.detached { await Self.run(started: started, task: task) }
            RigNote.write("rig.log", "detached: perform returns at \(Self.seconds(since: started)) s")
        #endif
    }

    #if !WIDGET_EXTENSION
        private static func run(started: Date, task: RigBackgroundTask) async {
            let echo = Task { await RigProbe.run(label: "detached-echo") }
            for second in 1...40 {
                try? await Task.sleep(for: .seconds(1))
                let remaining = await MainActor.run { UIApplication.shared.backgroundTimeRemaining }
                var line = "detached: +\(second) s alive, app state \(RigProbe.appState), background time remaining \(describe(remaining))"
                if [2, 6, 12].contains(second) {
                    WidgetCenter.shared.reloadTimelines(ofKind: "Rig")
                    line += "; asked a reload"
                }
                RigNote.write("rig.log", line)
            }
            let summary = await echo.value
            RigNote.write("rig.log", "detached: done after \(seconds(since: started)) s; echo: \(summary)")
            task.end()
        }

        private static func seconds(since start: Date) -> String { String(format: "%.1f", Date().timeIntervalSince(start)) }

        private static func describe(_ remaining: TimeInterval) -> String {
            remaining > 1_000_000 ? "unlimited" : String(format: "%.0f s", remaining)
        }
    #endif

    static func probe(label: String) async {
        #if WIDGET_EXTENSION
            // Not expected for either intent; logged so a wrong placement shows.
            let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("rig-extension.log")
            try? "\(Date()) \(label) ran in the widget extension\n".write(to: url, atomically: true, encoding: .utf8)
        #else
            _ = await RigProbe.run(label: label)
        #endif
        WidgetCenter.shared.reloadTimelines(ofKind: "Rig")
    }
}
