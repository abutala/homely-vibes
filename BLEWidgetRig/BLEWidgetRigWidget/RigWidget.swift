import AppIntents
import SwiftUI
import WidgetKit

/// Two buttons, the shape of AugustUnlock's widget: the left one probes
/// from the app's process in the background, the right one opens the app
/// and probes in the foreground. The outcome is in the app's `rig.log`.
@main
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
}

struct RigProvider: TimelineProvider {
    func placeholder(in context: Context) -> RigEntry { RigEntry(date: .now) }
    func getSnapshot(in context: Context, completion: @escaping (RigEntry) -> Void) { completion(RigEntry(date: .now)) }
    func getTimeline(in context: Context, completion: @escaping (Timeline<RigEntry>) -> Void) {
        completion(Timeline(entries: [RigEntry(date: .now)], policy: .never))
    }
}

struct RigView: View {
    let entry: RigEntry

    var body: some View {
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
        }
        .tint(.primary)
        .containerBackground(.fill.tertiary, for: .widget)
    }

    private func icon(_ name: String) -> some View {
        Image(systemName: name).font(.system(size: 34)).padding(8)
    }
}
