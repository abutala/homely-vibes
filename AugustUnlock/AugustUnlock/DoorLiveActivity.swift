import ActivityKit
import Foundation

/// One widget tap's Live Activity on the Dynamic Island and the Lock Screen,
/// run from the app's process in the background (a `LiveActivityIntent` may
/// start one there; measured on the phone, Logbook 2026-11-07). Stages go
/// through one stream to one task, so updates land in order and none lands
/// after the end. Nothing here can fail the unlock: a refused start is
/// logged and the tap runs without an activity.
final class DoorLiveActivity: Sendable {
    private let activity: Activity<DoorUnlockAttributes>
    private let stages: AsyncStream<DoorStage>.Continuation
    private let updates: Task<Void, Never>

    private init(activity: Activity<DoorUnlockAttributes>) {
        self.activity = activity
        let (stream, stages) = AsyncStream.makeStream(of: DoorStage.self)
        self.stages = stages
        updates = Task {
            for await stage in stream {
                await activity.update(Self.content(stage, seconds: nil, for: activity.attributes))
            }
        }
    }

    /// Ends any activity an earlier tap left (a process that died mid-tap, or
    /// one still in its hold), then starts this tap's at its first stage. Call
    /// only when no other tap runs in this process: overlapping activities
    /// empty the Island early (Logbook 2026-11-07). With no old one (the
    /// usual tap) nothing waits; otherwise the old ones get up to 0.5 s to
    /// end (an end took 14–23 ms on the phone), so two never show at once
    /// and a hung end cannot hold the unlock.
    static func start(door: String, first: DoorStage, at tap: Date) async -> DoorLiveActivity? {
        let old = Activity<DoorUnlockAttributes>.activities
        for activity in old {
            Task { await activity.end(nil, dismissalPolicy: .immediate) }
        }
        let giveUp = ContinuousClock.now + .milliseconds(500)
        while old.contains(where: { $0.activityState == .active }), ContinuousClock.now < giveUp {
            try? await Task.sleep(for: .milliseconds(25))
        }
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            AppLog.note("live activity off in Settings")
            return nil
        }
        let attributes = DoorUnlockAttributes(door: door, tap: tap)
        do {
            let activity = try Activity.request(attributes: attributes, content: content(first, seconds: nil, for: attributes), pushType: nil)
            return DoorLiveActivity(activity: activity)
        } catch {
            AppLog.note("live activity refused: \(error.localizedDescription)")
            return nil
        }
    }

    nonisolated func show(_ stage: DoorStage) { stages.yield(stage) }

    /// The tap's result. The Island drops an ended activity; the Lock Screen
    /// keeps it for `DoorState.hold`, as the widget keeps its result.
    func end(_ stage: DoorStage, seconds: Double) async {
        stages.finish()
        await updates.value
        await activity.end(
            Self.content(stage, seconds: seconds, for: activity.attributes),
            dismissalPolicy: .after(Date().addingTimeInterval(DoorState.hold)))
    }

    private static func content(_ stage: DoorStage, seconds: Double?, for attributes: DoorUnlockAttributes)
        -> ActivityContent<DoorUnlockAttributes.ContentState>
    {
        // A tap is over by `runningLimit`; an activity not ended by then (its
        // process died) reads stale, never "Unlocking…" or "Locking…" for hours.
        ActivityContent(state: .init(stage: stage, seconds: seconds), staleDate: attributes.tap.addingTimeInterval(DoorState.runningLimit))
    }
}
