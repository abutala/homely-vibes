import AppIntents
import SwiftUI
import WidgetKit

/// A button per door, with no lock state shown. Each tap runs
/// `ToggleDoorIntent` in the app, which decides lock or unlock.
@main
struct AugustUnlockWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "Doors", provider: DoorsProvider()) { entry in
            DoorsView(entry: entry)
        }
        .configurationDisplayName("Doors")
        .description("Tap a door to unlock it. Tap again to lock it.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct DoorsEntry: TimelineEntry {
    let date: Date
    let names: [String]
}

/// One static entry: the names change only when the app's lock list does,
/// and the app reloads the widget then.
struct DoorsProvider: TimelineProvider {
    /// Used when the app's lock names can't be read (see `SharedLockList`).
    static let fallbackNames = ["Door 1", "Door 2"]

    func placeholder(in context: Context) -> DoorsEntry {
        DoorsEntry(date: .now, names: Self.fallbackNames)
    }

    func getSnapshot(in context: Context, completion: @escaping (DoorsEntry) -> Void) {
        completion(currentEntry())
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<DoorsEntry>) -> Void) {
        completion(Timeline(entries: [currentEntry()], policy: .never))
    }

    private func currentEntry() -> DoorsEntry {
        let names = SharedLockList.read().flatMap { $0.isEmpty ? nil : $0 } ?? Self.fallbackNames
        return DoorsEntry(date: .now, names: names)
    }
}

struct DoorsView: View {
    @Environment(\.widgetFamily) private var family
    let entry: DoorsEntry

    private var maxDoors: Int { family == .systemSmall ? 2 : 4 }

    var body: some View {
        let doors = Array(entry.names.prefix(maxDoors).enumerated())
        VStack(spacing: 8) {
            ForEach(doors, id: \.offset) { slot, name in
                Button(intent: ToggleDoorIntent(slot: slot)) {
                    Label(name, systemImage: "door.left.hand.open")
                        .font(.headline)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.roundedRectangle(radius: 14))
                .invalidatableContent()
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }
}
