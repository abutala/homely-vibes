import AppIntents
import SwiftUI
import WidgetKit

/// One full-width row: a coloured circle per door, named as August names it.
/// Each tap runs in the widget (`DoorIntents.swift`); the app never opens.
/// The widget shares no code or state with the app; it only reads the app's
/// sign-in (`WidgetCloud`).
@main
struct AugustUnlockWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "Doors", provider: DoorsProvider()) { entry in
            DoorsView(entry: entry)
        }
        .configurationDisplayName("Doors")
        .description("Tap a door to unlock it. Tap again to lock it.")
        .supportedFamilies([.systemMedium])
    }
}

struct DoorsEntry: TimelineEntry {
    struct Door {
        let name: String
        let display: DoorDisplay
    }

    let date: Date
    /// At most two, in `WidgetStore.locks` order.
    let doors: [Door]
    let message: String?
}

/// A timeline re-fetches the lock list, so a renamed or added lock shows up,
/// and an expired sign-in shows "Open the app to sign in" (a tap's final
/// reload fetches, so a failed tap shows it too). The reload a tap fires to
/// show "running" skips the fetch, and any fetch is capped at
/// `fetchDeadline`, so the tap's feedback never waits on the network; between reloads the only changes are expiries, so the timeline holds
/// the next one.
struct DoorsProvider: TimelineProvider {
    static let fetchDeadline: TimeInterval = 4

    func placeholder(in context: Context) -> DoorsEntry {
        DoorsEntry(date: .now, doors: [], message: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (DoorsEntry) -> Void) {
        completion(entry(at: .now, message: nil))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<DoorsEntry>) -> Void) {
        Task {
            var message: String?
            let running = shownLocks().contains { WidgetStore.record(for: $0.id).effective(at: Date()).running != nil }
            do {
                if !running {
                    WidgetStore.locks = try await withDeadline(seconds: Self.fetchDeadline) {
                        try await WidgetCloud.fetchLocks()
                    }
                }
            } catch WidgetCloud.Failure.signedOut {
                message = WidgetCloud.Failure.signedOut.localizedDescription
            } catch {
                message = WidgetStore.locks.isEmpty ? error.localizedDescription : nil
            }
            let now = Date()
            var entries = [entry(at: now, message: message)]
            let changes = shownLocks().compactMap { WidgetStore.record(for: $0.id).nextChange() }.filter { $0 > now }
            if let next = changes.min() {
                entries.append(entry(at: next, message: message))
            }
            completion(Timeline(entries: entries, policy: .atEnd))
        }
    }

    private func shownLocks() -> [WidgetCloud.Lock] {
        Array(WidgetStore.locks.prefix(2))
    }

    private func entry(at date: Date, message: String?) -> DoorsEntry {
        let doors = shownLocks().map { lock in
            DoorsEntry.Door(name: lock.name, display: DoorDisplay(WidgetStore.record(for: lock.id).effective(at: date)))
        }
        return DoorsEntry(date: date, doors: doors, message: message)
    }
}

struct DoorsView: View {
    let entry: DoorsEntry

    /// Each door is one button that fills its half of the widget: a tap
    /// anywhere outside a button is a widget-body tap, which opens the app.
    var body: some View {
        Group {
            if entry.doors.isEmpty {
                Text(entry.message ?? "Open the app to sign in").font(.footnote).foregroundStyle(.secondary)
            } else {
                VStack(spacing: 4) {
                    HStack(spacing: 0) {
                        ForEach(Array(entry.doors.enumerated()), id: \.offset) { position, door in
                            button(position: position, door: door)
                        }
                    }
                    if let message = entry.message {
                        Text(message).font(.caption2).foregroundStyle(.red)
                    }
                }
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }

    /// Bordered is the one button style that stays interactive in this
    /// install (`.plain` taps fall through to "open the app" — see the
    /// Logbook); a clear tint leaves only our circle visible.
    @ViewBuilder
    private func button(position: Int, door: DoorsEntry.Door) -> some View {
        let label = VStack(spacing: 6) {
            ZStack {
                Circle().fill(door.display.color)
                Image(systemName: door.display.symbol)
                    .font(.system(size: 30))
                    .foregroundStyle(.white)
            }
            .frame(width: 76, height: 76)
            Text(door.name).font(.caption).bold().foregroundStyle(.primary).lineLimit(1)
            Text(door.display.caption).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .invalidatableContent()
        if position == 0 {
            Button(intent: ToggleFirstDoorIntent()) { label }
                .buttonStyle(.borderedProminent).tint(.clear)
        } else {
            Button(intent: ToggleSecondDoorIntent()) { label }
                .buttonStyle(.borderedProminent).tint(.clear)
        }
    }
}
