import AppIntents
import SwiftUI
import WidgetKit

/// One full-width row: a coloured circle per door, from the state the app
/// and the widget share (`DoorStateStore`). Each tap runs in the widget
/// (`DoorIntents.swift`); the app never opens.
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
    let date: Date
    /// Per door, in `Doors.all` order.
    let displays: [DoorDisplay]
}

/// The app reloads the widget after each of its commands and the widget
/// after its own; between reloads the only changes are expiries, so the
/// timeline holds the next one.
struct DoorsProvider: TimelineProvider {
    func placeholder(in context: Context) -> DoorsEntry {
        DoorsEntry(date: .now, displays: Doors.all.map { _ in .unknown })
    }

    func getSnapshot(in context: Context, completion: @escaping (DoorsEntry) -> Void) {
        completion(entry(at: .now))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<DoorsEntry>) -> Void) {
        let now = Date()
        var entries = [entry(at: now)]
        let trust = DoorRecord.widgetUnlockedTrust
        let changes = records().compactMap { $0?.nextChange(after: now, trustUnlockedFor: trust) }.filter { $0 > now }
        if let next = changes.min() {
            entries.append(entry(at: next))
        }
        completion(Timeline(entries: entries, policy: .atEnd))
    }

    /// One record per door; nil when the app hasn't cached that lock yet.
    private func records() -> [DoorRecord?] {
        let locks = AugustClient.shared.cachedLocks ?? []
        let stored = DoorStateStore.read()
        return Doors.all.map { door in
            locks.indices.contains(door.slot) ? (stored[locks[door.slot].id] ?? DoorRecord(at: .distantPast)) : nil
        }
    }

    private func entry(at date: Date) -> DoorsEntry {
        let displays = records().map { record -> DoorDisplay in
            guard let record else { return .unknown }
            let now = record.effective(at: date, trustUnlockedFor: DoorRecord.widgetUnlockedTrust)
            if let running = now.running { return running ? .unlocking : .locking }
            switch now.state {
            case .locked: return .locked
            case .unlocked: return .unlocked
            case .unknown: return .unknown
            }
        }
        return DoorsEntry(date: date, displays: displays)
    }
}

struct DoorsView: View {
    let entry: DoorsEntry

    var body: some View {
        HStack(spacing: 32) {
            ForEach(Array(Doors.all.enumerated()), id: \.offset) { index, door in
                let display = entry.displays[index]
                VStack(spacing: 6) {
                    button(for: door, display: display)
                    Text(door.name).font(.caption).bold()
                    Text(display.caption).font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }

    /// Bordered is the one button style that stays interactive in this
    /// install (`.plain` taps fall through to "open the app" — see the Logbook).
    @ViewBuilder
    private func button(for door: Doors.Door, display: DoorDisplay) -> some View {
        let label = Image(systemName: display.isRunning ? "ellipsis" : display.symbol)
            .font(.system(size: 28))
            .frame(width: 44, height: 44)
            .invalidatableContent()
        switch door.slot {
        case 0:
            Button(intent: ToggleFrontDoorIntent()) { label }
                .buttonStyle(.borderedProminent).buttonBorderShape(.circle).tint(display.color)
        default:
            Button(intent: ToggleGarageIntent()) { label }
                .buttonStyle(.borderedProminent).buttonBorderShape(.circle).tint(display.color)
        }
    }
}
