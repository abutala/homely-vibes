import ActivityKit
import SwiftUI
import WidgetKit

/// A widget tap's Live Activity (`DoorLiveActivity` runs it from the app's
/// process). The Island: the stage's icon and a timer from the tap while it
/// runs, the result's caption at the end. The Lock Screen: the door's name
/// and the stage's caption. A tap whose process died before the end reads
/// "Check the door" once stale.
struct DoorActivityWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: DoorUnlockAttributes.self) { context in
            DoorActivityLockScreen(context: context)
                .padding()
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) { DoorStageIcon(stage: context.state.stage).font(.title2) }
                DynamicIslandExpandedRegion(.center) { Text(context.attributes.door).font(.headline).lineLimit(1) }
                DynamicIslandExpandedRegion(.trailing) { DoorTimer(context: context).font(.title3) }
                DynamicIslandExpandedRegion(.bottom) { Text(DoorActivityText.caption(context)).font(.subheadline) }
            } compactLeading: {
                DoorStageIcon(stage: context.state.stage)
            } compactTrailing: {
                DoorTimer(context: context).frame(maxWidth: 44)
            } minimal: {
                DoorStageIcon(stage: context.state.stage)
            }
        }
    }
}

enum DoorActivityText {
    static func caption(_ context: ActivityViewContext<DoorUnlockAttributes>) -> String {
        if context.isStale, !context.state.stage.isFinal { return "Check the door" }
        return context.state.stage.caption(seconds: context.state.seconds)
    }
}

struct DoorActivityLockScreen: View {
    let context: ActivityViewContext<DoorUnlockAttributes>

    var body: some View {
        HStack(spacing: 12) {
            DoorStageIcon(stage: context.state.stage).font(.title)
            VStack(alignment: .leading, spacing: 2) {
                Text(context.attributes.door).font(.headline).lineLimit(1)
                Text(DoorActivityText.caption(context)).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            DoorTimer(context: context).font(.title3)
        }
    }
}

/// Seconds since the tap while it runs, drawn by the system with no update
/// from the app; nothing once the result is in (the caption has the time).
struct DoorTimer: View {
    let context: ActivityViewContext<DoorUnlockAttributes>

    var body: some View {
        if context.state.stage.isFinal || context.isStale {
            EmptyView()
        } else {
            let tap = context.attributes.tap
            Text(timerInterval: tap...tap.addingTimeInterval(DoorState.runningLimit), countsDown: false, showsHours: false)
                .monospacedDigit()
        }
    }
}

struct DoorStageIcon: View {
    let stage: DoorStage

    var body: some View {
        let (name, color): (String, Color) = switch stage {
        case .unlocking: ("lock.fill", .secondary)
        case .bluetooth: ("dot.radiowaves.left.and.right", .blue)
        case .cloud: ("cloud.fill", .gray)
        case .unlocked: ("lock.open.fill", .green)
        case .failed: ("xmark.circle.fill", .red)
        case .noReply: ("questionmark.circle.fill", .orange)
        }
        Image(systemName: name).foregroundStyle(color).accessibilityLabel(stage.caption(seconds: nil))
    }
}
