import AppIntents
import SwiftUI
import WidgetKit

/// One full-width row: a gray circle per door. The widget can't read the
/// app's lock names or states under Sideloadly (see the Logbook), so the
/// labels are fixed and every circle shows "unknown". Each tap runs
/// `ToggleDoorIntent` in the app, which decides lock or unlock; while it runs,
/// iOS dims the tapped circle (`invalidatableContent`).
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
    /// Left to right. `slot` is the lock's index in the app's door order (by
    /// lock ID), where the main door sorts first — checked on the phone.
    static let doors: [(name: String, slot: Int)] = [("Garage", 1), ("Main door", 0)]

    var body: some View {
        HStack {
            ForEach(Self.doors, id: \.slot) { door in
                Button(intent: ToggleDoorIntent(slot: door.slot)) {
                    DoorCircle(name: door.name, display: .unknown, diameter: 92)
                        .frame(maxWidth: .infinity)
                        .invalidatableContent()
                }
                .buttonStyle(.plain)
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }
}
