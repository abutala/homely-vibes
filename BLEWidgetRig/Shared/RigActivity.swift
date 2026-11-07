import ActivityKit
import AppIntents
import Foundation
import os

/// The Live Activity probe's data. `tap` is static: the view draws a system
/// timer from it that ticks with no update from the app. `second` is what
/// the app's process last sent, so a sent count that falls behind the
/// timer on the phone means its background updates are coalesced.
nonisolated struct RigActivityAttributes: ActivityAttributes {
    nonisolated struct ContentState: Codable, Hashable, Sendable {
        var second: Int
        /// "echo…", then the probe's outcome ("ok in 1870 ms", "failed in …").
        var echo: String
        var finished: Bool
    }

    let tap: Date
}

/// The widget's fourth button, the measurement behind AugustUnlock's
/// Live Activity: the same modes as its unlock tap, plus
/// `LiveActivityIntent`, which Apple says lets `perform()` start an
/// activity with the app in the background. The work runs inside
/// `perform()`, as the unlock would, and stays under the ~30 s intent cap.
struct RigLiveActivityIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Probe with a Live Activity"
    static let isDiscoverable = false
    static let supportedModes: IntentModes = [.background, .foreground(.dynamic)]

    func perform() async throws -> some IntentResult {
        await RigLive.run()
        return .result()
    }
}

enum RigLive {
    /// Updates sent, one a second; 20 s plus the request fits the 28 s
    /// AugustUnlock gives a tap.
    static let seconds = 20
    /// How long the ended activity stays, as AugustUnlock's result hold.
    static let hold: TimeInterval = 12

    /// Starts the activity, runs the Bluetooth echo beside it, sends one
    /// update a second with the echo's state, then ends it. Every call is
    /// timed in `rig.log` under `live:`.
    static func run() async {
        #if WIDGET_EXTENSION
            let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("rig-extension.log")
            try? "\(Date()) live ran in the widget extension\n".write(to: url, atomically: true, encoding: .utf8)
        #else
            let tap = Date()
            let start = ContinuousClock.now
            RigNote.write("rig.log", "live: perform start, app state \(RigProbe.appState), activities enabled \(ActivityAuthorizationInfo().areActivitiesEnabled)")
            let activity: Activity<RigActivityAttributes>
            do {
                activity = try Activity.request(attributes: RigActivityAttributes(tap: tap), content: content(0, "echo\u{2026}", tap: tap), pushType: nil)
                RigNote.write("rig.log", "live: request ok in \(ms(since: start)) ms")
            } catch {
                RigNote.write("rig.log", "live: request FAILED in \(ms(since: start)) ms: \(error)")
                return
            }
            let echo = OSAllocatedUnfairLock<String?>(initialState: nil)
            let probe = Task {
                let summary = await RigProbe.run(label: "live-echo")
                echo.withLock { $0 = outcome(summary) }
            }
            for second in 1...seconds {
                try? await Task.sleep(until: start + .seconds(second), clock: .continuous)
                let sent = ContinuousClock.now
                let text = echo.withLock { $0 } ?? "echo\u{2026}"
                await activity.update(content(second, text, tap: tap))
                RigNote.write("rig.log", "live: +\(second) s sent, update took \(ms(since: sent)) ms, state \(activity.activityState), app state \(RigProbe.appState)")
            }
            await probe.value
            let final = content(seconds, echo.withLock { $0 } ?? "no echo", tap: tap, finished: true)
            await activity.end(final, dismissalPolicy: .after(Date().addingTimeInterval(hold)))
            RigNote.write("rig.log", "live: ended at \(ms(since: start)) ms, dismissal after \(Int(hold)) s")
        #endif
    }

    #if !WIDGET_EXTENSION
        private static func content(_ second: Int, _ echo: String, tap: Date, finished: Bool = false) -> ActivityContent<RigActivityAttributes.ContentState> {
            ActivityContent(
                state: RigActivityAttributes.ContentState(second: second, echo: echo, finished: finished),
                staleDate: tap.addingTimeInterval(30))
        }

        /// "live-echo: ok in 1870 ms [...]" → "ok in 1870 ms".
        private static func outcome(_ summary: String) -> String {
            let afterLabel = summary.split(separator: ":", maxSplits: 1).last.map(String.init) ?? summary
            return afterLabel.prefix { $0 != "[" }.trimmingCharacters(in: .whitespaces)
        }

        private static func ms(since start: ContinuousClock.Instant) -> Int {
            let elapsed = start.duration(to: .now).components
            return Int(elapsed.seconds) * 1000 + Int(elapsed.attoseconds / 1_000_000_000_000_000)
        }
    #endif
}
