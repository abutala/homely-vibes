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
    /// one still in its hold), then starts this tap's at "Unlocking…". Call
    /// only when no other tap runs in this process: overlapping activities
    /// empty the Island early (Logbook 2026-11-07). Nothing here waits: the
    /// old ones end on their own tasks, and the request returns at once
    /// (16–34 ms on the phone), so the unlock is not delayed.
    static func start(door: String, at tap: Date) -> DoorLiveActivity? {
        for old in Activity<DoorUnlockAttributes>.activities {
            Task { await old.end(nil, dismissalPolicy: .immediate) }
        }
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            AppLog.note("live activity off in Settings")
            return nil
        }
        let attributes = DoorUnlockAttributes(door: door, tap: tap)
        do {
            let activity = try Activity.request(attributes: attributes, content: content(.unlocking, seconds: nil, for: attributes), pushType: nil)
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
        // process died) reads stale, never "Unlocking…" for hours.
        ActivityContent(state: .init(stage: stage, seconds: seconds), staleDate: attributes.tap.addingTimeInterval(DoorState.runningLimit))
    }
}
