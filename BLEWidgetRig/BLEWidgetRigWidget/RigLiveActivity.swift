import ActivityKit
import SwiftUI
import WidgetKit

/// The Live button's activity. Every presentation draws two clocks side by
/// side: "sent", the second the app's process last sent, and "clock", a
/// system timer from the tap that ticks with no update. On the phone, sent
/// keeping pace with clock means background updates draw live; sent
/// falling behind means they are coalesced. A screen recording shows it.
struct RigLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: RigActivityAttributes.self) { context in
            RigLiveLockScreen(tap: context.attributes.tap, state: context.state)
                .padding()
                .activityBackgroundTint(Color.black.opacity(0.6))
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) { sent(context.state).font(.title3) }
                DynamicIslandExpandedRegion(.trailing) { clock(context.attributes.tap).font(.title3) }
                DynamicIslandExpandedRegion(.bottom) { Text(context.state.echo).font(.caption) }
            } compactLeading: {
                sent(context.state)
            } compactTrailing: {
                clock(context.attributes.tap).frame(maxWidth: 44)
            } minimal: {
                Text("\(context.state.second)").monospacedDigit()
            }
        }
    }
}

struct RigLiveLockScreen: View {
    let tap: Date
    let state: RigActivityAttributes.ContentState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                sent(state).font(.title2).bold()
                Spacer()
                clock(tap).font(.title2)
            }
            Text(state.finished ? "done · \(state.echo)" : state.echo).font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// The pushed count; its accessibility label lets the Simulator test find it.
private func sent(_ state: RigActivityAttributes.ContentState) -> some View {
    Text("sent +\(state.second)").monospacedDigit().accessibilityLabel("sent +\(state.second) s")
}

/// The system's own timer from the tap: drawn with no update from the app.
private func clock(_ tap: Date) -> some View {
    Text(timerInterval: tap...tap.addingTimeInterval(3600), countsDown: false, showsHours: false).monospacedDigit()
}
