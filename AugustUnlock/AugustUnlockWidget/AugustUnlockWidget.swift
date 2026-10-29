import AppIntents
import SwiftUI
import WidgetKit

/// One full-width row: a gray circle per door. The widget can't read the
/// app's lock names or states under Sideloadly (see the Logbook), so the
/// labels are fixed and every circle shows "unknown". Each tap runs
/// `ToggleDoorIntent` in the app, which decides lock or unlock.
@main
struct AugustUnlockWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "Doors", provider: DoorsProvider()) { _ in
            DoorsView()
        }
        .configurationDisplayName("Doors")
        .description("Tap a door to unlock it. Tap again to lock it.")
        .supportedFamilies([.systemMedium])
    }
}

/// The view never changes, so one entry that never expires.
struct DoorsProvider: TimelineProvider {
    struct Entry: TimelineEntry {
        let date: Date
    }

    func placeholder(in context: Context) -> Entry { Entry(date: .now) }

    func getSnapshot(in context: Context, completion: @escaping (Entry) -> Void) {
        completion(Entry(date: .now))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<Entry>) -> Void) {
        completion(Timeline(entries: [Entry(date: .now)], policy: .never))
    }
}

struct DoorsView: View {
    /// In the app's door order (by lock ID) — the order of the app's circles
    /// and of its "Change Lock" list, where Garage comes first. If those ever
    /// change order, these labels point at the wrong lock.
    static let doorNames = ["Garage", "Main door"]

    var body: some View {
        HStack {
            ForEach(Array(Self.doorNames.enumerated()), id: \.offset) { slot, name in
                Button(intent: ToggleDoorIntent(slot: slot)) {
                    DoorCircle(name: name, display: .unknown, diameter: 92)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.plain)
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }
}
