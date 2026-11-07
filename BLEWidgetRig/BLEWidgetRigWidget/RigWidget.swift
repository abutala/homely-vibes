import AppIntents
import SwiftUI
import WidgetKit

/// The rig's widget and the Live button's activity (`RigLiveActivity`).
@main
struct RigWidgets: WidgetBundle {
    var body: some Widget {
        RigWidget()
        RigLiveActivity()
    }
}

/// Four buttons, the shape of AugustUnlock's widget: the first probes
/// from the app's process in the background, the second opens the app and
/// probes in the foreground, the third returns at once and probes detached
/// (the "progress on the widget" measurement), the fourth starts a Live
/// Activity and updates it while it probes. The outcome is in the app's
/// `rig.log`; the provider's runs in the widget's `rig-widget.log`.
struct RigWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "Rig", provider: RigProvider()) { entry in
            RigView(entry: entry)
        }
        .configurationDisplayName("BLE Rig")
        .description("Probe the Mac's echo peripheral.")
        .supportedFamilies([.systemMedium])
    }
}

struct RigEntry: TimelineEntry {
    let date: Date
    /// When the last Detached tap started (`RigMark`), if any.
    let tapStarted: Date?

    /// "run 15:23:41.2 · tap +3.1 s": the provider's run time and its lag
    /// after the tap, drawn on the widget so a screenshot shows the lag too.
    var caption: String {
        let run = ISO8601DateFormatter.withFractionalSeconds.string(from: date).dropFirst(11).prefix(10)
        guard let tapStarted else { return "run \(run)" }
        return "run \(run) · tap +\(String(format: "%.1f", date.timeIntervalSince(tapStarted))) s"
    }
}

/// Every run is logged to the widget's own `rig-widget.log` with its lag
/// after the last Detached tap: the measurement of when a reload asked
/// after `perform()` returned is actually run.
struct RigProvider: TimelineProvider {
    func placeholder(in context: Context) -> RigEntry { RigEntry(date: .now, tapStarted: nil) }
    func getSnapshot(in context: Context, completion: @escaping (RigEntry) -> Void) { completion(entry("snapshot")) }
    func getTimeline(in context: Context, completion: @escaping (Timeline<RigEntry>) -> Void) {
        completion(Timeline(entries: [entry("timeline")], policy: .never))
    }

    private func entry(_ reason: String) -> RigEntry {
        let entry = RigEntry(date: .now, tapStarted: RigMark.get())
        RigNote.write("rig-widget.log", "\(reason): \(entry.caption)")
        return entry
    }
}

struct RigView: View {
    let entry: RigEntry

    var body: some View {
        VStack(spacing: 4) {
            buttons
            Text(entry.caption).font(.caption2).monospacedDigit().foregroundStyle(.secondary)
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }

    private var buttons: some View {
        HStack(spacing: 0) {
            VStack(spacing: 6) {
                Button(intent: RigBackgroundProbeIntent()) { icon("moon.fill") }.accessibilityLabel("Background")
                Text("Background").font(.caption).bold()
            }
            .frame(maxWidth: .infinity)
            VStack(spacing: 6) {
                Button(intent: RigForegroundProbeIntent()) { icon("sun.max.fill") }.accessibilityLabel("Foreground")
                Text("Foreground").font(.caption).bold()
            }
            .frame(maxWidth: .infinity)
            VStack(spacing: 6) {
                Button(intent: RigDetachedProbeIntent()) { icon("bolt.horizontal.fill") }.accessibilityLabel("Detached")
                Text("Detached").font(.caption).bold()
            }
            .frame(maxWidth: .infinity)
            VStack(spacing: 6) {
                Button(intent: RigLiveActivityIntent()) { icon("dot.radiowaves.left.and.right") }.accessibilityLabel("Live")
                Text("Live").font(.caption).bold()
            }
            .frame(maxWidth: .infinity)
        }
        .tint(.primary)
    }

    private func icon(_ name: String) -> some View {
        Image(systemName: name).font(.system(size: 34)).padding(8)
    }
}
